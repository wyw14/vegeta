package vegeta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// Compile-time checks that the method values satisfy the function types.
var (
	_ Encoder = (&CheckpointEncoder{}).Encode
	_ Decoder = (&CheckpointDecoder{}).Decode
)

var checkpointEncodings = []CheckpointEncoding{
	CheckpointGob,
	CheckpointJSON,
	CheckpointCSV,
}

func checkpointResult(seq uint64) *Result {
	return &Result{
		Attack:    "test",
		Seq:       seq,
		Code:      200,
		Timestamp: time.Unix(0, int64(seq)*int64(time.Millisecond)),
		Latency:   5 * time.Millisecond,
		BytesOut:  1000 + seq,
		BytesIn:   2000 + seq,
		Error:     "",
		Body:      []byte("hello world"),
		Method:    http.MethodGet,
		URL:       "http://example.com/",
		Headers:   http.Header{"X-Test": {"yes"}},
	}
}

func encodeAll(t *testing.T, w io.Writer, enc Encoder, rs []*Result) {
	t.Helper()
	for _, r := range rs {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode seq %d: %v", r.Seq, err)
		}
	}
}

func decodeAll(t *testing.T, data []byte) ([]Result, *CheckpointDecoder) {
	t.Helper()
	d, err := NewCheckpointDecoder(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	var got []Result
	for {
		var r Result
		switch err := d.Decode(&r); {
		case err == nil:
			got = append(got, r)
		case errors.Is(err, io.EOF):
			return got, d
		default:
			t.Fatalf("decode #%d: %v", len(got), err)
		}
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	want := make([]*Result, 6)
	for i := range want {
		want[i] = checkpointResult(uint64(i) + 10) // constant digit count
	}

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			e, err := NewCheckpointEncoder(&buf, enc)
			if err != nil {
				t.Fatal(err)
			}
			encodeAll(t, &buf, e.Encode, want)
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}

			got, d := decodeAll(t, buf.Bytes())
			if len(got) != len(want) {
				t.Fatalf("decoded %d results, want %d", len(got), len(want))
			}
			for i := range got {
				if !got[i].Equal(*want[i]) {
					t.Fatalf("result %d mismatch:\ngot  %+v\nwant %+v", i, got[i], *want[i])
				}
			}

			stats := d.Stats()
			if !stats.Complete || stats.Truncated {
				t.Fatalf("bad stats: %+v", stats)
			}
			if stats.Version != CheckpointVersion || stats.Encoding != enc {
				t.Fatalf("bad header stats: %+v", stats)
			}
			if stats.Count != uint64(len(want)) ||
				stats.FirstSeq != want[0].Seq || stats.LastSeq != want[len(want)-1].Seq {
				t.Fatalf("bad range stats: %+v", stats)
			}
		})
	}
}

func TestCheckpointEmptyStream(t *testing.T) {
	t.Parallel()

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			e, err := NewCheckpointEncoder(&buf, enc)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}

			got, d := decodeAll(t, buf.Bytes())
			if len(got) != 0 {
				t.Fatalf("decoded %d results from empty stream", len(got))
			}
			stats := d.Stats()
			if !stats.Complete || stats.Truncated || stats.Count != 0 {
				t.Fatalf("bad stats: %+v", stats)
			}
		})
	}
}

func TestCheckpointTruncation(t *testing.T) {
	t.Parallel()

	want := make([]*Result, 5)
	for i := range want {
		want[i] = checkpointResult(uint64(i) + 10)
	}

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			// Record the byte offset at which every complete frame ends.
			var rec recordingWriter
			e, err := NewCheckpointEncoder(&rec, enc)
			if err != nil {
				t.Fatal(err)
			}
			boundaries := make([]int, 0, len(want))
			for _, r := range want {
				if err := e.Encode(r); err != nil {
					t.Fatal(err)
				}
				boundaries = append(boundaries, rec.Len())
			}
			noTrailer := append([]byte(nil), rec.Bytes()...)
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			full := rec.Bytes()
			trailerStart := boundaries[len(boundaries)-1]

			// Exact frame boundary, no trailer: all prefix frames decode and
			// the stream is not considered truncated (nothing was discarded).
			for k, end := range boundaries {
				got, d := decodeAll(t, noTrailer[:end])
				if len(got) != k+1 {
					t.Fatalf("boundary %d: decoded %d results", end, len(got))
				}
				if s := d.Stats(); s.Truncated || s.Complete {
					t.Fatalf("boundary %d: bad stats %+v", end, s)
				}
				if !got[k].Equal(*want[k]) {
					t.Fatalf("boundary %d: last result mismatch", end)
				}
			}

			// One byte before each boundary: the torn frame is discarded and
			// recovery stops at the previous complete frame.
			for k, end := range boundaries {
				cut := end - 1
				got, d := decodeAll(t, noTrailer[:cut])
				if len(got) != k {
					t.Fatalf("cut %d: decoded %d results, want %d", cut, len(got), k)
				}
				if !d.Stats().Truncated {
					t.Fatalf("cut %d: expected truncated recovery", cut)
				}
			}

			// Full stream: complete trailer verified.
			got, d := decodeAll(t, full)
			if len(got) != len(want) || !d.Stats().Complete {
				t.Fatalf("full stream: %d results, stats %+v", len(got), d.Stats())
			}

			// Trailer torn at various points: all frames survive, recovery is
			// flagged as truncated and the trailer is not marked complete.
			for _, cut := range []int{trailerStart + 1, trailerStart + 7, len(full) - 1} {
				got, d = decodeAll(t, full[:cut])
				if len(got) != len(want) {
					t.Fatalf("trailer cut %d: decoded %d results", cut, len(got))
				}
				if s := d.Stats(); !s.Truncated || s.Complete {
					t.Fatalf("trailer cut %d: bad stats %+v", cut, s)
				}
			}
		})
	}
}

func TestCheckpointCorruption(t *testing.T) {
	t.Parallel()

	want := make([]*Result, 4)
	for i := range want {
		want[i] = checkpointResult(uint64(i) + 10)
	}

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			e, err := NewCheckpointEncoder(&buf, enc)
			if err != nil {
				t.Fatal(err)
			}
			encodeAll(t, &buf, e.Encode, want)
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}

			// Flip a byte inside the first frame's payload: more data follows,
			// so this is corruption rather than a torn tail.
			bad := append([]byte(nil), buf.Bytes()...)
			bad[streamHeaderLen+frameHeaderLen+2] ^= 0xFF
			d, err := NewCheckpointDecoder(bytes.NewReader(bad))
			if err != nil {
				t.Fatal(err)
			}
			var r Result
			if err := d.Decode(&r); !errors.Is(err, ErrCheckpointDigest) {
				t.Fatalf("got %v, want ErrCheckpointDigest", err)
			}

			// Tamper with the trailer digest: frames decode, then it fails.
			bad = append([]byte(nil), buf.Bytes()...)
			bad[len(bad)-1] ^= 0xFF
			d2, err := NewCheckpointDecoder(bytes.NewReader(bad))
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < len(want); i++ {
				var r Result
				if err := d2.Decode(&r); err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
			}
			if err := d2.Decode(&r); !errors.Is(err, ErrCheckpointTrailer) {
				t.Fatalf("got %v, want ErrCheckpointTrailer", err)
			}
		})
	}
}

func TestCheckpointTornLastFrameRecoveredAsTruncation(t *testing.T) {
	t.Parallel()

	want := make([]*Result, 3)
	for i := range want {
		want[i] = checkpointResult(uint64(i) + 10)
	}

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			e, err := NewCheckpointEncoder(&buf, enc)
			if err != nil {
				t.Fatal(err)
			}
			encodeAll(t, &buf, e.Encode, want) // no trailer

			// Corrupt the final frame with nothing after it: it is
			// indistinguishable from a torn write and must be recovered as
			// truncation rather than a hard error.
			bad := append([]byte(nil), buf.Bytes()...)
			bad[len(bad)-1] ^= 0xFF
			got, d := decodeAll(t, bad)
			if len(got) != len(want)-1 {
				t.Fatalf("decoded %d results, want %d", len(got), len(want)-1)
			}
			if !d.Stats().Truncated {
				t.Fatal("expected truncated recovery")
			}
			for i := range got {
				if !got[i].Equal(*want[i]) {
					t.Fatalf("result %d mismatch", i)
				}
			}
		})
	}
}

func TestCheckpointSequenceValidation(t *testing.T) {
	t.Parallel()

	t.Run("encoder", func(t *testing.T) {
		t.Parallel()
		var e *CheckpointEncoder

		e, _ = NewCheckpointEncoder(io.Discard, CheckpointJSON)
		if err := e.Encode(checkpointResult(1)); err != nil {
			t.Fatal(err)
		}
		if err := e.Encode(checkpointResult(1)); !errors.Is(err, ErrCheckpointSequence) {
			t.Fatalf("duplicate: got %v", err)
		}

		e, _ = NewCheckpointEncoder(io.Discard, CheckpointJSON)
		if err := e.Encode(checkpointResult(2)); err != nil {
			t.Fatal(err)
		}
		if err := e.Encode(checkpointResult(1)); !errors.Is(err, ErrCheckpointSequence) {
			t.Fatalf("out of order: got %v", err)
		}

		// Gaps are allowed.
		e, _ = NewCheckpointEncoder(io.Discard, CheckpointGob)
		if err := e.Encode(checkpointResult(5)); err != nil {
			t.Fatal(err)
		}
		if err := e.Encode(checkpointResult(100)); err != nil {
			t.Fatalf("gap rejected: %v", err)
		}
	})

	t.Run("decoder", func(t *testing.T) {
		t.Parallel()

		// Hand-crafted frames with duplicate and out of order labels.
		for _, seqs := range [][]uint64{{1, 1}, {1, 2, 2}, {1, 3, 2}} {
			var buf bytes.Buffer
			writeRawHeader(t, &buf, CheckpointJSON)
			for _, seq := range seqs {
				writeRawFrame(t, &buf, CheckpointJSON, seq, checkpointResult(seq))
			}
			d, err := NewCheckpointDecoder(&buf)
			if err != nil {
				t.Fatal(err)
			}
			var r Result
			for i := 0; i < len(seqs)-1; i++ {
				if err := d.Decode(&r); err != nil {
					t.Fatalf("seqs %v: frame %d: %v", seqs, i, err)
				}
			}
			if err := d.Decode(&r); !errors.Is(err, ErrCheckpointSequence) {
				t.Fatalf("seqs %v: got %v", seqs, err)
			}
		}
	})
}

func TestCheckpointPayloadLabelMismatch(t *testing.T) {
	t.Parallel()

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			writeRawHeader(t, &buf, enc)
			writeRawFrame(t, &buf, enc, 5, checkpointResult(6))

			d, err := NewCheckpointDecoder(&buf)
			if err != nil {
				t.Fatal(err)
			}
			var r Result
			if err := d.Decode(&r); !errors.Is(err, ErrCheckpointDigest) {
				t.Fatalf("got %v, want ErrCheckpointDigest", err)
			}
		})
	}
}

func TestCheckpointHeaderValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, io.EOF},
		{"partial header", []byte("VGT"), io.ErrUnexpectedEOF},
		{"bad magic", []byte("XXXXX\x01\x01\x00"), ErrCheckpointMagic},
		{"bad version", []byte("VGTCP\x02\x01\x00"), ErrCheckpointVersion},
		{"bad encoding", []byte("VGTCP\x01\x09\x00"), ErrCheckpointEncoding},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCheckpointDecoder(bytes.NewReader(tc.data))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := NewCheckpointEncoder(io.Discard, CheckpointEncoding(99)); !errors.Is(err, ErrCheckpointEncoding) {
		t.Fatalf("encoder: got %v", err)
	}
}

func TestCheckpointTruncatedHugeLength(t *testing.T) {
	t.Parallel()

	// A corrupted frame header claiming a multi-GB payload on a tiny stream
	// must be recovered as truncation without allocating the claimed length.
	var buf bytes.Buffer
	writeRawHeader(t, &buf, CheckpointJSON)
	var hdr [frameHeaderLen]byte
	hdr[0] = frameTag
	binary.BigEndian.PutUint64(hdr[1:9], 1)
	binary.BigEndian.PutUint64(hdr[9:17], 1)
	binary.BigEndian.PutUint32(hdr[17:21], 0xFFFFFFFF)
	buf.Write(hdr[:])
	buf.WriteString("{truncated")

	d, err := NewCheckpointDecoder(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var r Result
	if err := d.Decode(&r); !errors.Is(err, io.EOF) || !d.Stats().Truncated {
		t.Fatalf("got err=%v truncated=%v, want io.EOF with truncation", err, d.Stats().Truncated)
	}
}

func TestCheckpointClosedEncoder(t *testing.T) {
	t.Parallel()

	e, err := NewCheckpointEncoder(io.Discard, CheckpointJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
	if err := e.Encode(checkpointResult(1)); !errors.Is(err, ErrCheckpointClosed) {
		t.Fatalf("got %v, want ErrCheckpointClosed", err)
	}
}

func TestCheckpointWriterOwnership(t *testing.T) {
	t.Parallel()

	t.Run("success never closes writer", func(t *testing.T) {
		t.Parallel()
		w := &closeTrackingWriter{}
		e, err := NewCheckpointEncoder(w, CheckpointJSON)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Encode(checkpointResult(1)); err != nil {
			t.Fatal(err)
		}
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		if w.closed {
			t.Fatal("encoder closed the caller-owned writer")
		}
	})

	t.Run("header failure never closes writer", func(t *testing.T) {
		t.Parallel()
		w := &failWriter{budget: 3}
		_, err := NewCheckpointEncoder(w, CheckpointJSON)
		if err == nil {
			t.Fatal("expected header write error")
		}
		if w.closed {
			t.Fatal("encoder closed the caller-owned writer")
		}
	})

	t.Run("frame failure never closes writer", func(t *testing.T) {
		t.Parallel()
		w := &failWriter{budget: streamHeaderLen + 10}
		e, err := NewCheckpointEncoder(w, CheckpointJSON)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Encode(checkpointResult(1)); err == nil {
			t.Fatal("expected frame write error")
		}
		if w.closed {
			t.Fatal("encoder closed the caller-owned writer")
		}
	})
}

func TestCheckpointDecoderForDetection(t *testing.T) {
	t.Parallel()

	for _, enc := range checkpointEncodings {
		enc := enc
		t.Run(enc.String(), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			e, err := NewCheckpointEncoder(&buf, enc)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Encode(checkpointResult(7)); err != nil {
				t.Fatal(err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}

			dec := DecoderFor(bytes.NewReader(buf.Bytes()))
			if dec == nil {
				t.Fatal("checkpoint stream not detected")
			}
			var r Result
			if err := dec.Decode(&r); err != nil {
				t.Fatal(err)
			}
			if r.Seq != 7 {
				t.Fatalf("got seq %d, want 7", r.Seq)
			}
			if err := dec.Decode(&r); err != io.EOF {
				t.Fatalf("got %v, want io.EOF", err)
			}
		})
	}
}

// recordingWriter records every byte and reports the current length after
// each frame so tests can derive exact frame boundary offsets.
type recordingWriter struct{ buf bytes.Buffer }

func (w *recordingWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *recordingWriter) Len() int                    { return w.buf.Len() }
func (w *recordingWriter) Bytes() []byte               { return w.buf.Bytes() }

// closeTrackingWriter records whether anything closed it.
type closeTrackingWriter struct {
	bytes.Buffer
	closed bool
}

func (w *closeTrackingWriter) Close() error {
	w.closed = true
	return nil
}

// failWriter accepts at most budget bytes before every Write fails. It also
// records Close calls so ownership rules can be asserted.
type failWriter struct {
	budget int
	closed bool
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		return 0, errors.New("disk full")
	}
	n := len(p)
	if n > w.budget {
		n = w.budget
	}
	w.budget -= n
	if n < len(p) {
		return n, errors.New("disk full")
	}
	return n, nil
}

func (w *failWriter) Close() error {
	w.closed = true
	return nil
}

// writeRawHeader writes a raw stream header (used for malformed-frame tests).
func writeRawHeader(t *testing.T, w io.Writer, enc CheckpointEncoding) {
	t.Helper()
	var hdr [streamHeaderLen]byte
	copy(hdr[:len(headerMagic)], headerMagic)
	hdr[5] = CheckpointVersion
	hdr[6] = byte(enc)
	if _, err := w.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
}

// writeRawFrame writes one frame whose label sequence number can differ from
// the Seq carried by its payload, allowing decoder validation to be tested.
func writeRawFrame(t *testing.T, w io.Writer, enc CheckpointEncoding, label uint64, r *Result) {
	t.Helper()
	var payload bytes.Buffer
	if err := enc.encode(&payload, r); err != nil {
		t.Fatal(err)
	}
	sum := frameDigest(CheckpointVersion, label, label, uint32(payload.Len()), payload.Bytes())

	var hdr [frameHeaderLen]byte
	hdr[0] = frameTag
	binary.BigEndian.PutUint64(hdr[1:9], label)
	binary.BigEndian.PutUint64(hdr[9:17], label)
	binary.BigEndian.PutUint32(hdr[17:21], uint32(payload.Len()))

	if _, err := w.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(sum[:]); err != nil {
		t.Fatal(err)
	}
}
