package vegeta

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually controlled, concurrency safe clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// diagSink collects diagnostics under a lock.
type diagSink struct {
	mu    sync.Mutex
	diags []ResolutionDiag
}

func (s *diagSink) fn(d ResolutionDiag) {
	s.mu.Lock()
	s.diags = append(s.diags, d)
	s.mu.Unlock()
}

func (s *diagSink) snapshot() []ResolutionDiag {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ResolutionDiag, len(s.diags))
	copy(out, s.diags)
	return out
}

func (s *diagSink) staleCount() int {
	n := 0
	for _, d := range s.snapshot() {
		if d.Stale {
			n++
		}
	}
	return n
}

func TestResolutionCache_TTLAndHits(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	clk := newFakeClock()
	c := NewResolutionCache[string]("test", time.Minute,
		func(_ context.Context, key string) (string, error) {
			calls.Add(1)
			return "v:" + key, nil
		},
		WithClock(clk.now),
	)

	v, diag, err := c.Resolve(context.Background(), "k")
	if err != nil || v != "v:k" {
		t.Fatalf("first resolve: v=%q err=%v", v, err)
	}
	if diag.CacheHit || diag.FetchedAt.IsZero() {
		t.Fatalf("first resolve must be a load, got %+v", diag)
	}

	// Within the TTL the loader must not be invoked again.
	for i := 0; i < 5; i++ {
		v, diag, err = c.Resolve(context.Background(), "k")
		if err != nil || v != "v:k" {
			t.Fatalf("cached resolve: v=%q err=%v", v, err)
		}
		if !diag.CacheHit || diag.Age < 0 {
			t.Fatalf("expected fresh cache hit, got %+v", diag)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls within TTL: have %d, want 1", got)
	}

	// Past the TTL a refresh happens.
	clk.add(time.Minute + time.Nanosecond)
	v, diag, err = c.Resolve(context.Background(), "k")
	if err != nil || v != "v:k" {
		t.Fatalf("refresh resolve: v=%q err=%v", v, err)
	}
	if diag.CacheHit || diag.Stale {
		t.Fatalf("expected a fresh load after TTL, got %+v", diag)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls after TTL: have %d, want 2", got)
	}
}

func TestResolutionCache_TTLZeroNeverExpires(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	clk := newFakeClock()
	c := NewResolutionCache[int]("test", 0,
		func(_ context.Context, _ string) (int, error) {
			return int(calls.Add(1)), nil
		},
		WithClock(clk.now),
	)

	for i := 0; i < 3; i++ {
		if v, _, err := c.Resolve(context.Background(), "k"); err != nil || v != 1 {
			t.Fatalf("resolve %d: v=%d err=%v", i, v, err)
		}
		clk.add(1000 * time.Hour)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("ttl=0 must never refresh: calls=%d", got)
	}
}

func TestResolutionCache_Disabled(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := NewResolutionCache[int]("test", -1,
		func(_ context.Context, _ string) (int, error) {
			return int(calls.Add(1)), nil
		},
	)

	for i := 1; i <= 3; i++ {
		if v, _, err := c.Resolve(context.Background(), "k"); err != nil || v != i {
			t.Fatalf("resolve %d: v=%d err=%v", i, v, err)
		}
	}
	if c.Len() != 0 {
		t.Fatalf("disabled cache must not store entries, Len=%d", c.Len())
	}
}

func TestResolutionCache_SingleFlightColdMiss(t *testing.T) {
	t.Parallel()

	const waiters = 128

	var calls atomic.Int64
	started := make(chan struct{})
	proceed := make(chan struct{})

	c := NewResolutionCache[string]("test", time.Minute,
		func(_ context.Context, key string) (string, error) {
			calls.Add(1)
			close(started)
			<-proceed
			return "loaded:" + key, nil
		},
	)

	var wg sync.WaitGroup
	vals := make([]string, waiters)
	errs := make([]error, waiters)
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func(i int) {
			defer wg.Done()
			vals[i], _, errs[i] = c.Resolve(context.Background(), "hot")
		}(i)
	}

	<-started
	// Give waiters time to park on the in-flight call.
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("single flight violated during cold miss: %d loader calls", got)
	}
	close(proceed)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls after completion: %d, want 1", got)
	}
	for i := 0; i < waiters; i++ {
		if errs[i] != nil || vals[i] != "loaded:hot" {
			t.Fatalf("waiter %d got v=%q err=%v", i, vals[i], errs[i])
		}
	}
}

func TestResolutionCache_SingleFlightExpiredRefresh(t *testing.T) {
	t.Parallel()

	const waiters = 64

	var calls atomic.Int64
	clk := newFakeClock()
	started := make(chan struct{})
	proceed := make(chan struct{})

	c := NewResolutionCache[string]("test", time.Minute,
		func(_ context.Context, key string) (string, error) {
			n := calls.Add(1)
			if n == 2 {
				close(started)
				<-proceed
			}
			return fmt.Sprintf("v%d:%s", n, key), nil
		},
		WithClock(clk.now),
	)

	if v, _, err := c.Resolve(context.Background(), "k"); err != nil || v != "v1:k" {
		t.Fatalf("initial load: v=%q err=%v", v, err)
	}

	clk.add(time.Minute + time.Second)

	var wg sync.WaitGroup
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = c.Resolve(context.Background(), "k")
		}()
	}

	<-started
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 2 {
		t.Fatalf("expired refresh must be a single flight, calls=%d", got)
	}
	close(proceed)
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Fatalf("expired refresh must be a single flight: %d total calls", got)
	}
}

func TestResolutionCache_FollowerContextCancel(t *testing.T) {
	t.Parallel()

	// The leader is a goroutine parked behind an external gate.
	gate := make(chan struct{})
	c := NewResolutionCache[string]("test", time.Minute,
		func(_ context.Context, key string) (string, error) {
			<-gate
			return "done:" + key, nil
		},
	)

	go func() { _, _, _ = c.Resolve(context.Background(), "k") }()
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := c.Resolve(ctx, "k")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follower should observe its context error, got: %v", err)
	}

	close(gate)
	// The leader still completes and the value is cached.
	deadline, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	v, _, err := c.Resolve(deadline, "k")
	if err != nil || v != "done:k" {
		t.Fatalf("post-cancel resolve: v=%q err=%v", v, err)
	}
}

func TestResolutionCache_StaleOnRefreshError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	loadErr := errors.New("origin down")
	clk := newFakeClock()
	sink := &diagSink{}

	c := NewResolutionCache[string]("file", time.Minute,
		func(_ context.Context, key string) (string, error) {
			n := calls.Add(1)
			if n == 1 {
				return "old:" + key, nil
			}
			return "", loadErr
		},
		WithClock(clk.now),
		WithDiagnostics(sink.fn),
	)

	v, _, err := c.Resolve(context.Background(), "targets.txt")
	if err != nil || v != "old:targets.txt" {
		t.Fatalf("initial load: v=%q err=%v", v, err)
	}

	clk.add(time.Minute + time.Second)
	v, diag, err := c.Resolve(context.Background(), "targets.txt")
	if err != nil {
		t.Fatalf("stale value should be served without error, got: %v", err)
	}
	if v != "old:targets.txt" {
		t.Fatalf("served value %q is not the old value", v)
	}
	if !diag.Stale || !errors.Is(diag.RefreshError, loadErr) || diag.Age < time.Minute {
		t.Fatalf("expected stale diagnostic, got %+v", diag)
	}
	if n := sink.staleCount(); n != 1 {
		t.Fatalf("expected exactly one stale diagnostic, got %d (%+v)", n, sink.snapshot())
	}
}

func TestResolutionCache_StaleServedToAllSingleFlightWaiters(t *testing.T) {
	t.Parallel()

	const waiters = 32

	var calls atomic.Int64
	loadErr := errors.New("boom")
	clk := newFakeClock()
	started := make(chan struct{})
	proceed := make(chan struct{})
	c := NewResolutionCache[string]("file", time.Minute,
		func(_ context.Context, key string) (string, error) {
			if calls.Add(1) == 1 {
				return "good", nil
			}
			close(started)
			<-proceed
			return "", loadErr
		},
		WithClock(clk.now),
	)

	if _, _, err := c.Resolve(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	clk.add(time.Minute + time.Second)

	var wg sync.WaitGroup
	wg.Add(waiters)
	stale, fail := int32(0), int32(0)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			_, diag, err := c.Resolve(context.Background(), "k")
			switch {
			case err != nil:
				atomic.AddInt32(&fail, 1)
			case diag.Stale:
				atomic.AddInt32(&stale, 1)
			}
		}()
	}

	<-started
	time.Sleep(20 * time.Millisecond)
	close(proceed)
	wg.Wait()

	if stale != waiters || fail != 0 || calls.Load() != 2 {
		t.Fatalf("stale=%d fail=%d calls=%d", stale, fail, calls.Load())
	}
}

func TestResolutionCache_StaleWindowExceeded(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	loadErr := errors.New("origin down")
	clk := newFakeClock()
	c := NewResolutionCache[string]("file", time.Minute,
		func(_ context.Context, _ string) (string, error) {
			if calls.Add(1) == 1 {
				return "old", nil
			}
			return "", loadErr
		},
		WithClock(clk.now),
		WithStaleTTL(30*time.Second),
	)

	if _, _, err := c.Resolve(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}

	// Inside the stale window: keep serving stale.
	clk.add(time.Minute + 29*time.Second)
	if v, diag, err := c.Resolve(context.Background(), "k"); err != nil || v != "old" || !diag.Stale {
		t.Fatalf("within window: v=%q err=%v stale=%v", v, err, diag.Stale)
	}

	// Outside the window: hard failure.
	clk.add(2 * time.Second)
	v, diag, err := c.Resolve(context.Background(), "k")
	if !errors.Is(err, loadErr) {
		t.Fatalf("expected refresh error past stale window, got v=%q err=%v", v, err)
	}
	if diag.Stale {
		t.Fatalf("must not report stale when hard-expired")
	}
}

func TestResolutionCache_StaleDisabled(t *testing.T) {
	t.Parallel()

	calls := int64(0)
	clk := newFakeClock()
	c := NewResolutionCache[string]("file", time.Minute,
		func(_ context.Context, _ string) (string, error) {
			if atomic.AddInt64(&calls, 1) == 1 {
				return "old", nil
			}
			return "", errors.New("down")
		},
		WithClock(clk.now),
		WithStaleTTL(-1),
	)

	_, _, _ = c.Resolve(context.Background(), "k")
	clk.add(time.Minute + time.Second)
	if _, _, err := c.Resolve(context.Background(), "k"); err == nil {
		t.Fatal("expected error when stale serving is disabled")
	}
}

func TestResolutionCache_FirstLoadError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("no file")
	c := NewResolutionCache[string]("file", time.Minute,
		func(_ context.Context, _ string) (string, error) { return "", wantErr },
	)
	v, diag, err := c.Resolve(context.Background(), "k")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err=%v", err)
	}
	if v != "" || diag.Stale || !errors.Is(diag.RefreshError, wantErr) {
		t.Fatalf("unexpected v=%q diag=%+v", v, diag)
	}
	if c.Len() != 0 {
		t.Fatalf("failed first load must not populate the cache")
	}
}

func TestResolutionCache_RetriesWhileStale(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	clk := newFakeClock()
	c := NewResolutionCache[int]("file", time.Minute,
		func(_ context.Context, _ string) (int, error) {
			switch calls.Add(1) {
			case 1:
				return 1, nil
			case 2, 3:
				return 0, errors.New("down")
			default:
				return 2, nil
			}
		},
		WithClock(clk.now),
	)

	resolve := func(want int, stale bool) {
		t.Helper()
		v, diag, err := c.Resolve(context.Background(), "k")
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if v != want || diag.Stale != stale {
			t.Fatalf("v=%d stale=%v, want %d stale=%v", v, diag.Stale, want, stale)
		}
	}

	resolve(1, false)
	clk.add(time.Minute + time.Second)
	resolve(1, true) // refresh #2 fails, stale served
	clk.add(time.Minute)
	resolve(1, true) // refresh #3 fails, stale served and retried
	clk.add(time.Minute)
	resolve(2, false) // refresh #4 succeeds
}

func TestResolutionCache_Invalidate(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := NewResolutionCache[int]("file", 0,
		func(_ context.Context, _ string) (int, error) {
			return int(calls.Add(1)), nil
		},
	)
	_, _, _ = c.Resolve(context.Background(), "k")
	_, _, _ = c.Resolve(context.Background(), "k")
	c.Invalidate("k")
	v, _, err := c.Resolve(context.Background(), "k")
	if err != nil || v != 2 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}

func TestResolutionCache_ConcurrentStress(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	clk := newFakeClock()
	c := NewResolutionCache[int]("test", 10*time.Millisecond,
		func(_ context.Context, key string) (int, error) {
			n := calls.Add(1)
			if n%7 == 0 {
				return 0, fmt.Errorf("transient %d", n)
			}
			return int(n), nil
		},
		WithClock(clk.now),
	)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				v, _, err := c.Resolve(context.Background(), "k")
				if err == nil && v <= 0 {
					t.Errorf("got zero value without error")
					return
				}
				if j%3 == 0 {
					clk.add(5 * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
}

func TestAuthScope_DefaultIsolation(t *testing.T) {
	t.Parallel()

	var loadsA, loadsB atomic.Int64
	cA := NewResolutionCache[string]("file", 0,
		func(_ context.Context, _ string) (string, error) {
			return fmt.Sprintf("attack-A-%d", loadsA.Add(1)), nil
		},
	)
	cB := NewResolutionCache[string]("file", 0,
		func(_ context.Context, _ string) (string, error) {
			return fmt.Sprintf("attack-B-%d", loadsB.Add(1)), nil
		},
	)

	if cA.Scope() == cB.Scope() || !cA.Scope().Valid() || !cB.Scope().Valid() {
		t.Fatalf("caches must get distinct valid scopes: %q %q", cA.Scope(), cB.Scope())
	}

	vA, _, _ := cA.Resolve(context.Background(), "same-key")
	vB, _, _ := cB.Resolve(context.Background(), "same-key")
	if vA == vB {
		t.Fatalf("private resolutions leaked across attacks: %q == %q", vA, vB)
	}
	if vA != "attack-A-1" || vB != "attack-B-1" {
		t.Fatalf("each attack must load its own value: %q %q", vA, vB)
	}
}

func TestAuthScope_SharedScopeAndKeyNamespaces(t *testing.T) {
	t.Parallel()

	scope := NewAuthScope()
	values := map[string]string{
		"nsA": "credential-A",
		"nsB": "credential-B",
	}
	newCache := func(ns string) *ResolutionCache[string] {
		return NewResolutionCache[string]("file", 0,
			func(_ context.Context, key string) (string, error) {
				return values[ns] + ":" + key, nil
			},
			WithAuthScope(scope),
			WithKeyNamespace(ns),
		)
	}

	cA, cB := newCache("nsA"), newCache("nsB")
	vA, _, _ := cA.Resolve(context.Background(), "targets")
	vB, _, _ := cB.Resolve(context.Background(), "targets")
	if vA == vB {
		t.Fatalf("different credential namespaces must not share entries")
	}
	if vA != "credential-A:targets" || vB != "credential-B:targets" {
		t.Fatalf("unexpected values: %q %q", vA, vB)
	}
}

func TestAuthScope_MaskedString(t *testing.T) {
	t.Parallel()

	s := NewAuthScope()
	str := s.String()
	if str == s.id || len(str) > 24 {
		t.Fatalf("scope token must be masked in String(), got %q", str)
	}
	var zero AuthScope
	if zero.Valid() {
		t.Fatal("zero scope reported valid")
	}
}

func TestPrivateAuthFingerprint(t *testing.T) {
	t.Parallel()

	hdr := func(auth string) http.Header {
		h := http.Header{}
		if auth != "" {
			h.Set("Authorization", auth)
		}
		h.Set("X-Trace", "trace-value")
		return h
	}

	fp1 := PrivateAuthFingerprint(hdr("Bearer token-1"), nil)
	fp2 := PrivateAuthFingerprint(hdr("Bearer token-1"), nil)
	fp3 := PrivateAuthFingerprint(hdr("Bearer token-2"), nil)
	fpNone := PrivateAuthFingerprint(hdr(""), nil)

	if fp1 != fp2 {
		t.Fatal("identical credentials must fingerprint identically")
	}
	if fp1 == fp3 || fp1 == fpNone {
		t.Fatal("different credentials must not collide")
	}

	// Non-auth headers are irrelevant to the fingerprint.
	h := hdr("Bearer x")
	h.Set("X-Other", "a")
	h2 := hdr("Bearer x")
	h2.Set("X-Other", "b")
	if PrivateAuthFingerprint(h, nil) != PrivateAuthFingerprint(h2, nil) {
		t.Fatal("non-auth headers changed the credential fingerprint")
	}

	// Case sensitive header keys used by vegeta must still be recognized.
	caseHdr := http.Header{"authorization": {"Bearer z"}}
	if PrivateAuthFingerprint(caseHdr, nil) == fpNone {
		t.Fatal("lowercase Authorization header not recognized as private auth")
	}

	// Proxy auth and cookies participate.
	ph := http.Header{}
	ph.Set("Proxy-Authorization", "Basic xx")
	ph.Set("Cookie", "sid=1")
	if PrivateAuthFingerprint(ph, nil) == fpNone {
		t.Fatal("proxy auth / cookies not recognized as private auth")
	}

	// TLS client certificate identity participates.
	tlsA := &tls.Config{Certificates: []tls.Certificate{{
		Leaf: &x509.Certificate{Raw: []byte("client-cert-a")},
	}}}
	tlsB := &tls.Config{Certificates: []tls.Certificate{{
		Leaf: &x509.Certificate{Raw: []byte("client-cert-b")},
	}}}
	if PrivateAuthFingerprint(nil, tlsA) == PrivateAuthFingerprint(nil, tlsB) {
		t.Fatal("distinct client certificates must not collide")
	}
}

func TestStripPrivateAuth(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("Cookie", "sid=abc")
	h.Set("X-Trace", "1")

	stripped := StripPrivateAuth(h)
	if len(stripped) != 1 || stripped.Get("X-Trace") != "1" {
		t.Fatalf("unexpected stripped headers: %v", stripped)
	}
	// Original untouched.
	if h.Get("Authorization") != "Bearer secret" {
		t.Fatal("StripPrivateAuth mutated the original header")
	}
}

func TestCloneTarget_DeepCopy(t *testing.T) {
	t.Parallel()

	orig := Target{
		Method: "GET",
		URL:    "https://example.test",
		Body:   []byte("body"),
		Header: http.Header{"Authorization": {"Bearer secret"}},
	}
	cp := cloneTarget(orig)

	cp.Header.Set("Authorization", "Bearer tampered")
	cp.Header.Add("X-New", "v")
	cp.Body[0] = 'X'

	if orig.Header.Get("Authorization") != "Bearer secret" {
		t.Fatal("header map aliased across clone")
	}
	if len(orig.Header) != 1 {
		t.Fatal("clone header additions leaked into original")
	}
	if string(orig.Body) != "body" {
		t.Fatal("body aliased across clone")
	}
}

func TestTemplateTargetCache_RefreshAndDeepCopy(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	templates := []Target{{
		Method: "GET",
		URL:    "https://a.example",
		Header: http.Header{"Authorization": {"Bearer A"}},
	}}
	c := NewTemplateTargetCache("tmpl", time.Minute, templates, WithClock(clk.now))
	ct := NewCachedTargeter(c, "tmpl")

	var got Target
	if err := ct.decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://a.example" || got.Header.Get("Authorization") != "Bearer A" {
		t.Fatalf("unexpected target: %+v", got)
	}

	// Mutating the served target must not poison the cache or later copies.
	got.Header.Set("Authorization", "Bearer TAMPERED")
	var got2 Target
	if err := ct.decode(&got2); err != nil {
		t.Fatal(err)
	}
	if got2.Header.Get("Authorization") != "Bearer A" {
		t.Fatalf("private header leaked through cached target: %q", got2.Header.Get("Authorization"))
	}

	// After TTL the cache re-snapshots the caller's templates.
	templates[0].URL = "https://b.example"
	clk.add(time.Minute + time.Second)
	var got3 Target
	if err := ct.decode(&got3); err != nil {
		t.Fatal(err)
	}
	if got3.URL != "https://b.example" {
		t.Fatalf("refresh did not pick up template change: %s", got3.URL)
	}
}

func TestTemplateTargetCache_EmptyRefreshKeepsStale(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	templates := []Target{{Method: "GET", URL: "https://a.example"}}
	c := NewTemplateTargetCache("tmpl", time.Minute, templates, WithClock(clk.now))
	ct := NewCachedTargeter(c, "tmpl")

	var tgt Target
	if err := ct.decode(&tgt); err != nil {
		t.Fatal(err)
	}

	templates = templates[:0]
	clk.add(time.Minute + time.Second)

	var tgt2 Target
	if err := ct.decode(&tgt2); err != nil {
		t.Fatalf("empty template refresh should keep stale set, got %v", err)
	}
	if tgt2.URL != "https://a.example" {
		t.Fatalf("stale target not served: %+v", tgt2)
	}
}

func TestCachedTargeter_NilTarget(t *testing.T) {
	t.Parallel()

	c := NewTemplateTargetCache("tmpl", 0, []Target{{Method: "GET", URL: "https://a.example"}})
	ct := NewCachedTargeter(c, "tmpl")
	if err := ct.decode(nil); err != ErrNilTarget {
		t.Fatalf("have %v, want %v", err, ErrNilTarget)
	}
}

func writeTargetsFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileTargetCache_RefreshReadsFileAgain(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	path := writeTargetsFile(t, "targets.txt", "GET https://foo.example/1\nGET https://foo.example/2\n")

	c, err := NewFileTargetCache(path, HTTPTargetFormat, nil, nil, time.Minute, WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	ct := NewCachedTargeter(c, path)

	tgts, diag, err := c.Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if len(tgts) != 2 || diag.CacheHit {
		t.Fatalf("unexpected initial resolve: %d targets diag=%+v", len(tgts), diag)
	}

	// File grows while the cached entry is fresh: change must not be visible.
	if err := os.WriteFile(path, []byte("GET https://foo.example/1\nGET https://foo.example/2\nGET https://foo.example/3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tgt Target
	if err := ct.decode(&tgt); err != nil {
		t.Fatal(err)
	}
	if tgt.URL == "https://foo.example/3" {
		t.Fatal("fresh cache served a target that did not exist at load time")
	}

	// After TTL the file is re-read.
	clk.add(time.Minute + time.Second)
	tgts, _, err = c.Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(tgts) != 3 {
		t.Fatalf("refresh did not re-read file: %d targets", len(tgts))
	}
}

func TestFileTargetCache_StaleWhenFileDisappears(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(path, []byte(`{"method":"GET","url":"https://foo.example/1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := NewFileTargetCache(path, JSONTargetFormat, nil, nil, time.Minute, WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	tgts, _, err := c.Resolve(context.Background(), path)
	if err != nil || len(tgts) != 1 {
		t.Fatalf("initial load: tgts=%v err=%v", tgts, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clk.add(time.Minute + time.Second)

	tgts, diag, err := c.Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("missing file must serve stale targets, got err=%v", err)
	}
	if !diag.Stale || diag.RefreshError == nil {
		t.Fatalf("expected stale diagnostic with refresh error, got %+v", diag)
	}
	if len(tgts) != 1 || tgts[0].URL != "https://foo.example/1" {
		t.Fatalf("stale targets mismatch: %+v", tgts)
	}
}

func TestFileTargetCache_DefaultHeadersAndAuth(t *testing.T) {
	t.Parallel()

	path := writeTargetsFile(t, "targets.txt", "GET https://foo.example/\n")
	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("X-Team", "sre")

	c, err := NewFileTargetCache(path, HTTPTargetFormat, nil, h, 0)
	if err != nil {
		t.Fatal(err)
	}
	tgts, _, err := c.Resolve(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := tgts[0].Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("default auth header missing: %q", got)
	}
	if got := tgts[0].Header.Get("X-Team"); got != "sre" {
		t.Fatalf("default header missing: %q", got)
	}

	// Cached targets must not alias the caller's header map.
	h.Set("Authorization", "Bearer rotated")
	if got := tgts[0].Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("cached target header aliased caller map: %q", got)
	}
}

func TestFileTargetCache_InvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewFileTargetCache("stdin", HTTPTargetFormat, nil, nil, time.Minute); err == nil {
		t.Fatal("stdin caching must be rejected")
	}
	if _, err := NewFileTargetCache("targets.txt", "yaml", nil, nil, time.Minute); err == nil {
		t.Fatal("unknown format must be rejected")
	}
}

type fakeHostResolver struct {
	mu    sync.Mutex
	calls int
	fn    func(host string) ([]string, error)
}

func (r *fakeHostResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	r.calls++
	fn := r.fn
	r.mu.Unlock()
	return fn(host)
}

func TestHostResolutionCache_TTLStaleAndCopy(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	res := &fakeHostResolver{}
	res.fn = func(string) ([]string, error) { return []string{"1.1.1.1", "2.2.2.2"}, nil }

	c := NewHostResolutionCache(time.Minute, res, WithClock(clk.now))

	ips, diag, err := ResolveHost(context.Background(), c, "host.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || diag.CacheHit {
		t.Fatalf("unexpected initial resolve: %v %+v", ips, diag)
	}

	// Mutating the returned slice must not corrupt the cache.
	ips[0] = "9.9.9.9"
	ips2, _, err := ResolveHost(context.Background(), c, "host.example")
	if err != nil || ips2[0] != "1.1.1.1" {
		t.Fatalf("cached addresses mutated: %v err=%v", ips2, err)
	}
	if res.calls != 1 {
		t.Fatalf("expected cached lookup, calls=%d", res.calls)
	}

	// Refresh failure keeps the old addresses and is diagnosed.
	res.fn = func(string) ([]string, error) { return nil, errors.New("dns server unreachable") }
	clk.add(time.Minute + time.Second)
	ips3, diag, err := ResolveHost(context.Background(), c, "host.example")
	if err != nil {
		t.Fatalf("stale addresses should be served: %v", err)
	}
	if !diag.Stale || len(ips3) != 2 || ips3[0] != "1.1.1.1" {
		t.Fatalf("unexpected stale resolve: %v %+v", ips3, diag)
	}

	// Empty answers are lookup errors.
	c2 := NewHostResolutionCache(time.Minute, HostResolverFunc(func(_ context.Context, _ string) ([]string, error) {
		return nil, nil
	}))
	if _, _, err := c2.Resolve(context.Background(), "nobody.example"); err == nil {
		t.Fatal("empty lookup result must be an error")
	}
}

// TestDNSCaching_StaleOnRefreshFailure verifies the Attacker wiring end to
// end: expired DNS refreshes that fail keep traffic flowing to the last
// known address and surface a diagnostic.
func TestDNSCaching_StaleOnRefreshError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := u.Port()

	var (
		mu          sync.Mutex
		failRefresh bool
	)
	sink := &diagSink{}
	atk := NewAttacker(
		KeepAlive(false), // force a fresh dial per request
		ResolutionDiagnostics(sink.fn),
	)
	atk.hostResolver = HostResolverFunc(func(_ context.Context, host string) ([]string, error) {
		mu.Lock()
		fail := failRefresh
		mu.Unlock()
		if fail {
			return nil, errors.New("simulated DNS outage")
		}
		if host != "cached.target.example" {
			t.Errorf("unexpected host: %s", host)
		}
		return []string{"127.0.0.1"}, nil
	})
	DNSCaching(50 * time.Millisecond)(atk)

	targetURL := "http://cached.target.example:" + port
	tr := NewStaticTargeter(Target{Method: "GET", URL: targetURL})
	atkObj := &attack{name: "cache-stale", began: time.Now()}

	hit := func() *Result {
		t.Helper()
		r := atk.hit(tr, atkObj)
		if r.Error != "" {
			t.Fatalf("unexpected result error: %s", r.Error)
		}
		return r
	}

	hit()
	if atk.hostCache.Len() != 1 {
		t.Fatalf("host address not cached: %d entries", atk.hostCache.Len())
	}

	// Wait for the entry to expire and break the resolver.
	time.Sleep(70 * time.Millisecond)
	mu.Lock()
	failRefresh = true
	mu.Unlock()

	for i := 0; i < 3; i++ {
		hit()
		time.Sleep(60 * time.Millisecond)
	}
	if n := sink.staleCount(); n == 0 {
		t.Fatalf("expected stale-serve diagnostics during DNS outage, got %d", n)
	}

	// Once the resolver recovers, refreshes succeed again and diagnostics
	// about stale serving stop.
	mu.Lock()
	failRefresh = false
	mu.Unlock()
	time.Sleep(70 * time.Millisecond)
	hit()
}

// TestDNSCaching_IsolationAcrossAttackers makes sure two attackers never
// share resolver state or private scopes.
func TestDNSCaching_IsolationAcrossAttackers(t *testing.T) {
	t.Parallel()

	a := NewAttacker(DNSCaching(time.Minute))
	b := NewAttacker(DNSCaching(time.Minute))

	if a.hostCache == nil || b.hostCache == nil {
		t.Fatal("host cache not installed")
	}
	if a.hostCache == b.hostCache {
		t.Fatal("host cache shared across attackers")
	}
	if a.hostCache.Scope() == b.hostCache.Scope() {
		t.Fatal("host cache auth scope shared across attackers")
	}
}

// TestDNSCaching_Disabled preserves the no-cache behavior for negative ttl.
func TestDNSCaching_Disabled(t *testing.T) {
	t.Parallel()

	a := NewAttacker(DNSCaching(-1))
	if a.hostCache != nil {
		t.Fatal("host cache must not be installed when ttl < 0")
	}
}
