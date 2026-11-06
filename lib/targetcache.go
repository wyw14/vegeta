package vegeta

// Target resolution cache.
//
// This file implements a concurrency safe, TTL based cache for the three
// kinds of target resolution results vegeta deals with:
//
//   - template targets: in-memory Target blueprints,
//   - file targets:     Target sets parsed from a targets file,
//   - resolver results:  dynamic (DNS) host name lookups.
//
// When a cached entry expires, concurrent callers are coalesced into a
// single in-flight refresh ("single flight"). If the refresh fails and a
// previous value is still within its stale-use window, that value keeps
// being served and the failure is reported through ResolutionDiag.
//
// Private authentication isolation: every cache is, by default, bound to a
// unique, unexported AuthScope, and entry keys are additionally namespaced
// with it. Caches therefore have to be created per attack (never as package
// level globals) so credentials attached to targets of one attack can never
// be served to another attack. Callers that resolve targets carrying
// per-target credentials can namespace entries further with the fingerprint
// returned by PrivateAuthFingerprint through WithKeyNamespace.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Target resolution source identifiers. They label ResolutionDiag values
// emitted by the caches built in this package.
const (
	// TemplateTargetSource is the source label for cached in-memory target
	// templates.
	TemplateTargetSource = "template"
	// FileTargetSource is the source label for targets parsed out of files.
	FileTargetSource = "file"
	// ResolverTargetSource is the source label for cached dynamic resolver
	// (DNS) results.
	ResolverTargetSource = "resolver"
)

// ResolutionDiag carries diagnostic information about a single cache
// resolution. It is returned by ResolutionCache.Resolve and, when
// configured, delivered to the WithDiagnostics sink.
type ResolutionDiag struct {
	// Source identifies the kind of resolution (one of the *TargetSource
	// constants).
	Source string
	// Key is the unscoped key that was resolved.
	Key string
	// FetchedAt is when the served value was last successfully fetched.
	FetchedAt time.Time
	// ResolvedAt is when this resolution happened.
	ResolvedAt time.Time
	// Age is the age of the served value at resolution time.
	Age time.Duration
	// CacheHit reports whether the value was served from a fresh entry
	// without invoking the loader.
	CacheHit bool
	// Stale reports whether the served value had expired but was kept
	// because the refresh failed within the stale-use window.
	Stale bool
	// RefreshError is the error that caused a stale value to be served.
	// It is nil on fresh hits and successful refreshes.
	RefreshError error
}

func (d ResolutionDiag) String() string {
	switch {
	case d.Stale:
		return fmt.Sprintf("%s target cache: serving stale %q (%s old) after refresh failure: %s",
			d.Source, d.Key, d.Age.Round(time.Millisecond), d.RefreshError)
	case d.CacheHit:
		return fmt.Sprintf("%s target cache: fresh hit for %q (%s old)",
			d.Source, d.Key, d.Age.Round(time.Millisecond))
	case d.RefreshError != nil:
		return fmt.Sprintf("%s target cache: refresh of %q failed: %s",
			d.Source, d.Key, d.RefreshError)
	default:
		return fmt.Sprintf("%s target cache: refreshed %q", d.Source, d.Key)
	}
}

// ResolveFunc loads the value associated with key from the origin source.
type ResolveFunc[V any] func(ctx context.Context, key string) (V, error)

// AuthScope identifies the private credential set a cache is bound to. The
// zero value is not a valid scope; NewResolutionCache generates a unique
// scope per cache unless one is explicitly provided through WithAuthScope.
//
// Because scopes are random unexported tokens and every cached key is
// namespaced with its scope, entries can never be shared across caches that
// were created for different attacks.
type AuthScope struct {
	id string
}

// NewAuthScope returns a fresh, cryptographically random AuthScope. Create
// one per attack and pass it with WithAuthScope when several caches must
// share the same attack boundary.
func NewAuthScope() AuthScope {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable; a time based fallback
		// still keeps scopes distinct, which is the safety property here.
		return AuthScope{id: fmt.Sprintf("t%d", time.Now().UnixNano())}
	}
	return AuthScope{id: hex.EncodeToString(b[:])}
}

// Valid reports whether s was produced by NewAuthScope.
func (s AuthScope) Valid() bool { return s.id != "" }

// String returns a masked representation; the full token is never exposed so
// it cannot leak through diagnostics or logs.
func (s AuthScope) String() string {
	if len(s.id) < 8 {
		return "auth-scope(invalid)"
	}
	return "auth-scope(" + s.id[:8] + "…)"
}

// CacheOption configures a ResolutionCache.
type CacheOption func(*cacheConfig)

type cacheConfig struct {
	staleTTL time.Duration
	scope    AuthScope
	ns       string
	onDiag   func(ResolutionDiag)
	now      func() time.Time
}

// WithStaleTTL bounds for how long an expired entry may still be served when
// refreshes keep failing, measured after the fresh TTL. A zero value (the
// default) allows stale entries to be served indefinitely, until a refresh
// succeeds; a negative value disables serving stale values entirely. The
// stale TTL also doubles as the refresh retry cooldown after a failure;
// when it is zero the fresh TTL is used as cooldown instead.
func WithStaleTTL(d time.Duration) CacheOption {
	return func(c *cacheConfig) { c.staleTTL = d }
}

// WithAuthScope binds the cache to an explicit attack scope. Without it,
// NewResolutionCache mints a unique scope for the cache.
func WithAuthScope(scope AuthScope) CacheOption {
	return func(c *cacheConfig) { c.scope = scope }
}

// WithKeyNamespace further namespaces every cache key. It is used to bind
// entries to a private credential fingerprint (see PrivateAuthFingerprint)
// so identically keyed targets resolved with different credentials never
// alias one another.
func WithKeyNamespace(ns string) CacheOption {
	return func(c *cacheConfig) { c.ns = ns }
}

// WithDiagnostics installs a sink invoked whenever an entry is refreshed, a
// refresh fails or a stale value is served. Fresh cache hits do not invoke
// the sink. The sink must be safe for concurrent use.
func WithDiagnostics(fn func(ResolutionDiag)) CacheOption {
	return func(c *cacheConfig) { c.onDiag = fn }
}

// WithClock overrides the clock used for TTL decisions. It exists mainly to
// make TTL behavior deterministically testable.
func WithClock(now func() time.Time) CacheOption {
	return func(c *cacheConfig) { c.now = now }
}

// ResolutionCache is a concurrency safe, TTL based cache of target
// resolution results.
type ResolutionCache[V any] struct {
	source string
	ttl    time.Duration
	load   ResolveFunc[V]
	cfg    cacheConfig

	mu      sync.RWMutex
	entries map[string]*cacheEntry[V]
	calls   map[string]*inflightCall[V]
}

type cacheEntry[V any] struct {
	val V
	// fetchedAt is when val was last successfully loaded.
	fetchedAt time.Time
	// lastAttempt is when the last failed refresh happened. While recent,
	// further refreshes are suppressed (a refresh cooldown) and the stale
	// value keeps being served.
	lastAttempt time.Time
	lastErr     error
}

type inflightCall[V any] struct {
	done chan struct{}
	val  V
	diag ResolutionDiag
	err  error
}

// NewResolutionCache returns a ResolutionCache of the named source that
// caches load results for ttl.
//
// ttl semantics:
//   - ttl > 0: entries are fresh for ttl, then refreshed on demand;
//   - ttl == 0: entries never expire after their first successful load;
//   - ttl < 0: caching is disabled and load is invoked on every resolution
//     (concurrent identical resolutions are still coalesced).
func NewResolutionCache[V any](source string, ttl time.Duration, load ResolveFunc[V], opts ...CacheOption) *ResolutionCache[V] {
	if load == nil {
		panic("vegeta: ResolutionCache requires a non-nil load function")
	}
	cfg := cacheConfig{now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	if !cfg.scope.Valid() {
		cfg.scope = NewAuthScope()
	}

	return &ResolutionCache[V]{
		source:  source,
		ttl:     ttl,
		load:    load,
		cfg:     cfg,
		entries: make(map[string]*cacheEntry[V]),
		calls:   make(map[string]*inflightCall[V]),
	}
}

// Scope returns the attack scope the cache is bound to.
func (c *ResolutionCache[V]) Scope() AuthScope { return c.cfg.scope }

// Len returns the number of currently cached entries.
func (c *ResolutionCache[V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Invalidate drops the cached value for key, if any, forcing the next
// Resolve to reload it from the origin.
func (c *ResolutionCache[V]) Invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, c.scopedKey(key))
	c.mu.Unlock()
}

// Resolve returns the value associated with key.
//
// Fresh entries are returned directly. Expired and missing entries trigger a
// single flight refresh: only one caller invokes the loader while concurrent
// callers wait for its result. If the refresh fails but a previous value is
// still within the stale-use window, the previous value is returned with a
// ResolutionDiag whose Stale field is true.
//
// After a failed refresh, further refreshes are suppressed for a cooldown
// (the stale TTL, falling back to the fresh TTL) to avoid hammering a
// failing origin; the stale value keeps being served during that window.
func (c *ResolutionCache[V]) Resolve(ctx context.Context, key string) (V, ResolutionDiag, error) {
	if c.ttl < 0 {
		v, err := c.resolveFreshOnly(ctx, key)
		return v, ResolutionDiag{
			Source: c.source, Key: key, ResolvedAt: c.cfg.now(),
			RefreshError: err,
		}, err
	}

	now := c.cfg.now()
	skey := c.scopedKey(key)

	c.mu.RLock()
	if v, diag, err, served := c.fastPathLocked(key, skey, now); served {
		c.mu.RUnlock()
		return v, diag, err
	}
	call, waiting := c.calls[skey]
	c.mu.RUnlock()
	if waiting {
		return c.await(ctx, key, call)
	}

	// Become the leader of the single flight refresh, unless another
	// goroutine raced us to it.
	c.mu.Lock()
	now = c.cfg.now()
	if v, diag, err, served := c.fastPathLocked(key, skey, now); served {
		c.mu.Unlock()
		return v, diag, err
	}
	if call, waiting = c.calls[skey]; waiting {
		c.mu.Unlock()
		return c.await(ctx, key, call)
	}
	call = &inflightCall[V]{done: make(chan struct{})}
	c.calls[skey] = call
	c.mu.Unlock()

	val, err := c.load(ctx, key)

	c.mu.Lock()
	delete(c.calls, skey)
	resolvedAt := c.cfg.now()

	if err == nil {
		c.entries[skey] = &cacheEntry[V]{val: val, fetchedAt: resolvedAt}
		c.mu.Unlock()
		diag := ResolutionDiag{
			Source: c.source, Key: key, FetchedAt: resolvedAt, ResolvedAt: resolvedAt,
		}
		c.emit(diag)
		call.set(val, diag, nil)
		return val, diag, nil
	}

	// Refresh failed: serve the previous value inside its stale-use window,
	// otherwise propagate the refresh error.
	var zero V
	diag := ResolutionDiag{
		Source: c.source, Key: key, ResolvedAt: resolvedAt, RefreshError: err,
	}
	old, hadOld := c.entries[skey]
	if hadOld {
		age := resolvedAt.Sub(old.fetchedAt)
		old.lastAttempt = resolvedAt
		old.lastErr = err
		diag.FetchedAt = old.fetchedAt
		diag.Age = age
		if c.serveStale(age) {
			c.mu.Unlock()
			diag.Stale = true
			c.emit(diag)
			call.set(old.val, diag, nil)
			return old.val, diag, nil
		}
	}
	c.mu.Unlock()

	c.emit(diag)
	call.set(zero, diag, err)
	return zero, diag, err
}

// fastPathLocked serves a resolution without invoking the loader when the
// entry is fresh, or when a recent failed refresh is within its cooldown.
// The returned error is nil for fresh and stale-serving resolutions and
// equals the cached refresh error when the stale-use window has elapsed.
func (c *ResolutionCache[V]) fastPathLocked(key, skey string, now time.Time) (V, ResolutionDiag, error, bool) {
	var zero V

	e, ok := c.entries[skey]
	if !ok {
		return zero, ResolutionDiag{}, nil, false
	}

	age := now.Sub(e.fetchedAt)
	if c.ttl == 0 || age < c.ttl {
		return e.val, ResolutionDiag{
			Source: c.source, Key: key, FetchedAt: e.fetchedAt,
			ResolvedAt: now, Age: age, CacheHit: true,
		}, nil, true
	}

	if c.inCooldown(e, now) {
		diag := ResolutionDiag{
			Source: c.source, Key: key, FetchedAt: e.fetchedAt,
			ResolvedAt: now, Age: age, RefreshError: e.lastErr,
		}
		if c.serveStale(age) {
			diag.Stale = true
			return e.val, diag, nil, true
		}
		return zero, diag, e.lastErr, true
	}

	return zero, ResolutionDiag{}, nil, false
}

// resolveFreshOnly implements the caching-disabled path: no entries are read
// or stored, but concurrent resolutions of the same key still share one
// loader invocation.
func (c *ResolutionCache[V]) resolveFreshOnly(ctx context.Context, key string) (V, error) {
	var zero V

	skey := c.scopedKey(key)

	c.mu.RLock()
	call, waiting := c.calls[skey]
	c.mu.RUnlock()
	if !waiting {
		c.mu.Lock()
		if call, waiting = c.calls[skey]; !waiting {
			call = &inflightCall[V]{done: make(chan struct{})}
			c.calls[skey] = call
		}
		c.mu.Unlock()
	}

	if !waiting {
		val, err := c.load(ctx, key)
		diag := ResolutionDiag{Source: c.source, Key: key, ResolvedAt: c.cfg.now()}
		c.mu.Lock()
		delete(c.calls, skey)
		c.mu.Unlock()
		if err != nil {
			diag.RefreshError = err
			c.emit(diag)
			call.set(zero, diag, err)
		} else {
			c.emit(diag)
			call.set(val, diag, nil)
		}
	}

	v, _, err := c.await(ctx, key, call)
	return v, err
}

func (c *ResolutionCache[V]) await(ctx context.Context, key string, call *inflightCall[V]) (V, ResolutionDiag, error) {
	var zero V
	select {
	case <-call.done:
		return call.val, call.diag, call.err
	case <-ctx.Done():
		return zero, ResolutionDiag{
			Source: c.source, Key: key, ResolvedAt: c.cfg.now(),
			RefreshError: ctx.Err(),
		}, ctx.Err()
	}
}

func (c *ResolutionCache[V]) emit(diag ResolutionDiag) {
	if c.cfg.onDiag != nil {
		c.cfg.onDiag(diag)
	}
}

// inCooldown reports whether a failed refresh for e happened recently
// enough that another refresh should be suppressed.
func (c *ResolutionCache[V]) inCooldown(e *cacheEntry[V], now time.Time) bool {
	cd := c.refreshCooldown()
	return cd > 0 && !e.lastAttempt.IsZero() && now.Sub(e.lastAttempt) < cd
}

// refreshCooldown returns the minimum spacing between refresh attempts after
// a failure: the explicit stale TTL when positive, or the fresh TTL when
// stale serving is unbounded (stale TTL zero).
func (c *ResolutionCache[V]) refreshCooldown() time.Duration {
	switch {
	case c.cfg.staleTTL < 0:
		return 0
	case c.cfg.staleTTL > 0:
		return c.cfg.staleTTL
	case c.ttl > 0:
		return c.ttl
	default:
		return 0
	}
}

// serveStale reports whether an entry of the given age may be served after a
// failed refresh.
func (c *ResolutionCache[V]) serveStale(age time.Duration) bool {
	switch {
	case c.cfg.staleTTL < 0:
		return false
	case c.cfg.staleTTL == 0:
		return true
	default:
		// With ttl == 0 entries never reach this path; guard anyway.
		if c.ttl < 0 {
			return false
		}
		return age <= c.ttl+c.cfg.staleTTL
	}
}

func (c *ResolutionCache[V]) scopedKey(key string) string {
	return c.cfg.scope.id + "\x00" + c.cfg.ns + "\x00" + key
}

func (call *inflightCall[V]) set(val V, diag ResolutionDiag, err error) {
	call.val, call.diag, call.err = val, diag, err
	close(call.done)
}

// privateAuthHeaderKeys are HTTP header keys that carry private
// authentication material. Comparison is done on canonical keys so that
// vegeta's case-sensitive header keys are still covered.
var privateAuthHeaderCanonical = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Cookie":              {},
}

func isPrivateAuthKey(k string) bool {
	_, ok := privateAuthHeaderCanonical[http.CanonicalHeaderKey(k)]
	return ok
}

// PrivateAuthFingerprint returns a stable, non reversible fingerprint of
// the private authentication material carried in HTTP request headers and a
// TLS client configuration. It is meant to namespace cache keys so that
// resolutions performed with different credentials can never share an
// entry. Headers other than Authorization, Proxy-Authorization and Cookie
// are ignored.
func PrivateAuthFingerprint(h http.Header, tc *tls.Config) string {
	w := sha256.New()

	if len(h) > 0 {
		keys := make([]string, 0, len(h))
		for k := range h {
			if isPrivateAuthKey(k) {
				keys = append(keys, k)
			}
		}
		// Sort the keys so the fingerprint is independent of map iteration
		// order. Insertion sort is enough, private header sets are small.
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
				keys[j-1], keys[j] = keys[j], keys[j-1]
			}
		}
		for _, k := range keys {
			vs := h[k]
			fmt.Fprintf(w, "%s=%d", k, len(vs))
			for _, v := range vs {
				fmt.Fprintf(w, "|%s", v)
			}
			w.Write([]byte{0})
		}
	}

	if tc != nil {
		for _, cert := range tc.Certificates {
			switch {
			case cert.Leaf != nil:
				w.Write(cert.Leaf.Raw)
			case len(cert.Certificate) > 0:
				w.Write(cert.Certificate[0])
			}
		}
	}

	sum := w.Sum(nil)
	return hex.EncodeToString(sum[:])
}

// StripPrivateAuth returns a copy of h without headers carrying private
// authentication material. It is useful when cached, non private target
// metadata must be shared while credentials stay request scoped.
func StripPrivateAuth(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if isPrivateAuthKey(k) {
			continue
		}
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// cloneTarget returns a deep copy of t so Target values handed out of a cache
// never share mutable Header maps or Body buffers with the cached snapshot.
// That keeps per-request authentication headers from mutating, or leaking
// through, a cached entry.
func cloneTarget(t Target) Target {
	cp := t
	if len(t.Body) != 0 {
		cp.Body = make([]byte, len(t.Body))
		copy(cp.Body, t.Body)
	}
	if len(t.Header) != 0 {
		h := make(http.Header, len(t.Header))
		for k, vs := range t.Header {
			cpvs := make([]string, len(vs))
			copy(cpvs, vs)
			h[k] = cpvs
		}
		cp.Header = h
	}
	return cp
}

// NewTemplateTargetCache returns a cache of an in-memory set of target
// templates. The templates slice is snapshotted (deep copied) on the first
// resolution and again at every refresh, which lets callers mutate the
// slice between TTLs. A refresh that yields no templates fails with
// ErrNoTargets, so a previously served set is kept by the stale-on-error
// policy.
func NewTemplateTargetCache(key string, ttl time.Duration, templates []Target, opts ...CacheOption) *ResolutionCache[[]Target] {
	return NewResolutionCache[[]Target](TemplateTargetSource, ttl,
		func(_ context.Context, _ string) ([]Target, error) {
			if len(templates) == 0 {
				return nil, ErrNoTargets
			}
			out := make([]Target, len(templates))
			for i := range templates {
				out[i] = cloneTarget(templates[i])
			}
			return out, nil
		}, opts...)
}

// NewFileTargetCache returns a cache of the Targets parsed from the targets
// file at path. The file is reopened and re-parsed (in the given format) on
// every refresh, so stdin cannot be cached. Default body and header values
// are merged into parsed targets exactly as NewHTTPTargeter/NewJSONTargeter
// do. The cache key is namespaced with a fingerprint of any private
// authentication headers so distinct credential sets never share entries.
func NewFileTargetCache(path, format string, body []byte, header http.Header, ttl time.Duration, opts ...CacheOption) (*ResolutionCache[[]Target], error) {
	switch {
	case path == "" || path == "stdin":
		return nil, errors.New("target cache: a file path is required; stdin cannot be re-read")
	case format != HTTPTargetFormat && format != JSONTargetFormat:
		return nil, fmt.Errorf("target cache: format %q isn't one of [%s]",
			format, TargetFormats)
	}

	// Bind the entry to the default headers' private credentials. The
	// namespace option is prepended so that an explicit WithKeyNamespace
	// passed by the caller still takes precedence (options apply in order).
	if len(header) > 0 {
		opts = append([]CacheOption{WithKeyNamespace(PrivateAuthFingerprint(header, nil))}, opts...)
	}

	load := func(_ context.Context, _ string) ([]Target, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		// Defensive copies: targeters assign these slices/maps onto produced
		// targets which outlive the call inside the cache.
		var defaultBody []byte
		if len(body) != 0 {
			defaultBody = make([]byte, len(body))
			copy(defaultBody, body)
		}
		var defaultHeader http.Header
		if len(header) > 0 {
			defaultHeader = make(http.Header, len(header))
			for k, vs := range header {
				cp := make([]string, len(vs))
				copy(cp, vs)
				defaultHeader[k] = cp
			}
		}

		var tr Targeter
		switch format {
		case JSONTargetFormat:
			tr = NewJSONTargeter(f, defaultBody, defaultHeader)
		case HTTPTargetFormat:
			tr = NewHTTPTargeter(f, defaultBody, defaultHeader)
		}

		tgts, err := ReadAllTargets(tr)
		if err != nil {
			return nil, err
		}
		return tgts, nil
	}

	return NewResolutionCache[[]Target](FileTargetSource, ttl, load, opts...), nil
}

// HostResolver resolves a host name to IP addresses. *net.Resolver
// implements it.
type HostResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// HostResolverFunc adapts a function to the HostResolver interface.
type HostResolverFunc func(ctx context.Context, host string) ([]string, error)

// LookupHost implements HostResolver.
func (fn HostResolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return fn(ctx, host)
}

// defaultHostResolver always dispatches through net.DefaultResolver at call
// time, so custom resolvers installed by the CLI before NewAttacker are
// honored.
var defaultHostResolver HostResolver = HostResolverFunc(func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
})

// NewHostResolutionCache returns a cache of dynamic resolver (DNS) results:
// host name to IP address sets. The cache has the same TTL and single
// flight semantics as any ResolutionCache and keeps serving the last known
// address set while refreshes fail, reporting each failure through
// diagnostics.
func NewHostResolutionCache(ttl time.Duration, r HostResolver, opts ...CacheOption) *ResolutionCache[[]string] {
	if r == nil {
		r = defaultHostResolver
	}
	return NewResolutionCache[[]string](ResolverTargetSource, ttl,
		func(ctx context.Context, host string) ([]string, error) {
			ips, err := r.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return append([]string(nil), ips...), nil
		}, opts...)
}

// ResolveHost resolves host through a host resolution cache and returns a
// copy of the cached addresses, so callers (for example dialers that
// reorder the slice) can never mutate cached state.
func ResolveHost(ctx context.Context, c *ResolutionCache[[]string], host string) ([]string, ResolutionDiag, error) {
	ips, diag, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, diag, err
	}
	return append([]string(nil), ips...), diag, nil
}

// CachedTargeter serves Targets round-robin out of a cached target set
// produced by a ResolutionCache. Every handed out Target is a deep copy, so
// concurrent workers can never mutate one another's (or the cache's)
// authentication headers and bodies.
type CachedTargeter struct {
	cache *ResolutionCache[[]Target]
	key   string
	idx   atomic.Int64
}

// NewCachedTargeter wraps a []Target resolution cache as a Targeter. All
// targets in the cache are expected to be stored under key.
func NewCachedTargeter(cache *ResolutionCache[[]Target], key string) *CachedTargeter {
	return &CachedTargeter{cache: cache, key: key}
}

// Targeter returns the function adapter used with Attacker.Attack.
func (ct *CachedTargeter) Targeter() Targeter { return ct.decode }

// Decode implements Targeter semantics.
func (ct *CachedTargeter) decode(tgt *Target) error {
	if tgt == nil {
		return ErrNilTarget
	}
	tgts, _, err := ct.cache.Resolve(context.Background(), ct.key)
	if err != nil {
		return err
	}
	if len(tgts) == 0 {
		return ErrNoTargets
	}
	i := ct.idx.Add(1) - 1
	*tgt = cloneTarget(tgts[i%int64(len(tgts))])
	return nil
}
