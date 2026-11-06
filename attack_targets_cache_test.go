package main

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

func startOKServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func baseAttackOpts(targetsf, outputf string) *attackOpts {
	return &attackOpts{
		headers:      headers{Header: make(http.Header)},
		proxyHeaders: headers{Header: make(http.Header)},
		laddr:        localAddr{&vegeta.DefaultLocalAddr},
		rate:         vegeta.Rate{Freq: 50, Per: time.Second},
		workers:      vegeta.DefaultWorkers,
		maxWorkers:   vegeta.DefaultMaxWorkers,
		maxBody:      vegeta.DefaultMaxBody,
		targetsf:     targetsf,
		outputf:      outputf,
		format:       vegeta.HTTPTargetFormat,
		promAddr:     "",
	}
}

func runAttackFile(t *testing.T, opts *attackOpts) vegeta.Metrics {
	t.Helper()

	outPath := filepath.Join(t.TempDir(), "results.bin")
	if opts.outputf == "" {
		opts.outputf = outPath
	}

	if err := attack(opts); err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	raw, err := os.ReadFile(opts.outputf)
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}

	var metrics vegeta.Metrics
	dec := vegeta.NewDecoder(bufio.NewReader(bytes.NewReader(raw)))
	for {
		var r vegeta.Result
		if err := dec.Decode(&r); err != nil {
			break
		}
		metrics.Add(&r)
	}
	metrics.Close()
	return metrics
}

func TestAttack_TargetsTTLValidation(t *testing.T) {
	t.Parallel()

	// -lazy combined with -targets-ttl is rejected.
	opts := baseAttackOpts("targets.txt", "")
	opts.lazy = true
	opts.targetsTTL = time.Second
	if err := attack(opts); err == nil || !strings.Contains(err.Error(), "-lazy") {
		t.Fatalf("expected lazy+ttl validation error, got %v", err)
	}

	// stdin combined with -targets-ttl is rejected.
	opts = baseAttackOpts("stdin", "")
	opts.targetsTTL = time.Second
	if err := attack(opts); err == nil || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("expected stdin+ttl validation error, got %v", err)
	}

	// Missing targets file fails fast.
	opts = baseAttackOpts(filepath.Join(t.TempDir(), "missing.txt"), "")
	opts.targetsTTL = time.Second
	if err := attack(opts); err == nil {
		t.Fatal("expected error for missing targets file")
	}
}

func TestAttack_TargetsTTLCachesFile(t *testing.T) {
	t.Parallel()

	srvURL := startOKServer(t)

	dir := t.TempDir()
	targetsPath := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsPath, []byte("GET "+srvURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := baseAttackOpts(targetsPath, "")
	opts.duration = 400 * time.Millisecond
	opts.targetsTTL = 0 // cache forever: edits to the file must be ignored

	// Rewrite the targets file mid-attack with an invalid target. With
	// ttl=0 the cached target set must keep being used.
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(targetsPath, []byte("GET http://127.0.0.1:1/\n"), 0o600)
	}()

	metrics := runAttackFile(t, opts)
	if metrics.Requests == 0 {
		t.Fatal("no requests recorded")
	}
	if metrics.Success != 1.0 {
		t.Fatalf("cached targets were not reused: success=%.2f statusCodes=%v errors=%d",
			metrics.Success, metrics.StatusCodes, len(metrics.Errors))
	}
}
