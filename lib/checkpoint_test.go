package vegeta

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testResult builds a distinctive, fully populated Result for a sequence.
func testResult(seq uint64) *Result {
	return &Result{
		Attack:    "checkpoint-test",
		Seq:       seq,
		Code:      200,
		Timestamp: time.Unix(0, int64(seq)*int64(time.Millisecond)),
		Latency:   time.Duration(seq) * time.Microsecond,
		BytesOut:  seq * 2,
		BytesIn:   seq * 3,
		Body:      []byte(fmt.Sprintf("body-%d", seq)),
		Method:    "GET",
		URL:       "http://vegeta.test/checkpoint",
		Headers:   http.Header{"X-Seq": []string{fmt.Sprintf("%d", seq)}},
	}
}

// openTempCheckpoint creates a fresh temp file opened as a checkpoint.
func openTempCheckpoint(t *testing.T) (*CheckpointEncoder, *os.File) {
	t.Helper()
	f, err := os.CreateTemp("", "vegeta-checkpoint-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(f.Name())
	})
	enc, err := OpenCheckpoint(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	return enc, f
}

// reopenCheckpoint opens an existing checkpoint file for append/resume.
func reopenCheckpoint(t *testing.T, name string) *CheckpointEncoder {
	t.Helper()
	f, err := os.OpenFile(name, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	enc, err := OpenCheckpoint(f)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// decodeCheckpoint decodes every record from a checkpoint path.
func decodeCheckpoint(t *testing.T, name string) []Result {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return decodeCheckpointReader(t, f)
}

func decodeCheckpointReader(t *testing.T, r io.Reader) []Result {
	t.Helper()
	dec := NewCheckpointDecoder(r)
	var got []Result
	for {
		var res Result
		switch err := dec.Decode(&res); {
		case err == nil:
			got = append(got, res)
		case errors.Is(err, io.EOF):
			return got
		default:
			t.Fatalf("unexpected decode error: %v", err)
		}
	}
}

// appendRawFrame appends a raw frame to buf and chains the digest. It lets
// tests craft on-disk streams that could never be produced by Encode.
func appendRawFrame(t *testing.T, buf []byte, prev *[checkpointDigestSize]byte, r *Result) []byte {
	t.Helper()
	var payload bytes.Buffer
	if err := gob.NewEncoder(&payload).Encode(r); err != nil {
		t.Fatal(err)
	}
	var hdr [checkpointFrameHdrSize]byte
	binary.BigEndian.PutUint64(hdr[:checkpointSeqSize], r.Seq)
	binary.BigEndian.PutUint32(hdr[checkpointSeqSize:], uint32(payload.Len()))
	dgt := checkpointDigest(*prev, r.Seq, hdr[checkpointSeqSize:], payload.Bytes())
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload.Bytes()...)
	buf = append(buf, dgt[:]...)
	*prev = dgt
	return buf
}

func checkpointHeader() []byte {
	h := make([]byte, 0, checkpointHeaderSize)
	h = append(h, checkpointMagic...)
	h = append(h, checkpointVersion)
	return h
}

// writeRawCheckpoint writes a crafted stream to a temp file and returns it.
func writeRawCheckpoint(t *testing.T, raw []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "vegeta-checkpoint-raw-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestCheckpointEmptyStream(t *testing.T) {
	t.Parallel()

	// A zero byte input is a valid empty stream for the decoder.
	dec := NewCheckpointDecoder(bytes.NewReader(nil))
	if err := dec.Decode(&Result{}); !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream: got %v, want io.EOF", err)
	}

	// Opening an empty file initializes the header and starts at seq 0.
	enc, f := openTempCheckpoint(t)
	if got, want := enc.Next(), uint64(0); got != want {
		t.Fatalf("Next on empty: got %d, want %d", got, want)
	}
	if seq, ok := enc.LastSeq(); ok {
		t.Fatalf("LastSeq on empty: got (%d, true), want false", seq)
	}
	name := f.Name()
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// A header-only stream decodes to zero records.
	if got := decodeCheckpoint(t, name); len(got) != 0 {
		t.Fatalf("header-only stream decoded %d records, want 0", len(got))
	}

	// Reopening an empty checkpoint still starts at seq 0 and accepts writes.
	enc2 := reopenCheckpoint(t, name)
	if got := enc2.Next(); got != 0 {
		t.Fatalf("Next after reopening empty: got %d, want 0", got)
	}
	if err := enc2.Encode(testResult(0)); err != nil {
		t.Fatal(err)
	}
	enc2.Close()
}

func TestCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	want := make([]Result, 0, 10)
	for seq := uint64(0); seq < 10; seq++ {
		r := testResult(seq)
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
		want = append(want, *r)
	}
	name := f.Name()
	enc.Close()
	f.Close()

	got := decodeCheckpoint(t, name)
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Fatalf("record %d mismatch:\ngot:  %+v\nwant: %+v", i, got[i], want[i])
		}
		if got[i].Seq != uint64(i) {
			t.Fatalf("record %d has seq %d, want strictly increasing order", i, got[i].Seq)
		}
	}
}

func TestCheckpointResumeFromLastConfirmed(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	all := make([]Result, 0, 100)
	for seq := uint64(0); seq < 50; seq++ {
		r := testResult(seq)
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
		all = append(all, *r)
	}
	name := f.Name()
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Recovery continues right after the last confirmed sequence number.
	enc2 := reopenCheckpoint(t, name)
	if got, want := enc2.Next(), uint64(50); got != want {
		t.Fatalf("Next after resume: got %d, want %d", got, want)
	}
	last, ok := enc2.LastSeq()
	if !ok || last != 49 {
		t.Fatalf("LastSeq after resume: got (%d, %v), want (49, true)", last, ok)
	}
	for seq := uint64(50); seq < 100; seq++ {
		r := testResult(seq)
		if err := enc2.Encode(r); err != nil {
			t.Fatal(err)
		}
		all = append(all, *r)
	}
	enc2.Close()

	got := decodeCheckpoint(t, name)
	if len(got) != len(all) {
		t.Fatalf("got %d records, want %d", len(got), len(all))
	}
	for i := range all {
		if !got[i].Equal(all[i]) {
			t.Fatalf("record %d mismatch:\ngot:  %+v\nwant: %+v", i, got[i], all[i])
		}
	}
}

func TestCheckpointDuplicateSequence(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	r0 := testResult(0)
	if err := enc.Encode(r0); err != nil {
		t.Fatal(err)
	}

	// A live duplicate sequence number is rejected and changes nothing.
	if err := enc.Encode(testResult(0)); !errors.Is(err, ErrCheckpointDuplicate) {
		t.Fatalf("duplicate write: got %v, want %v", err, ErrCheckpointDuplicate)
	}
	if got := enc.Next(); got != 1 {
		t.Fatalf("Next after duplicate: got %d, want 1", got)
	}
	name := f.Name()
	enc.Close()
	f.Close()

	got := decodeCheckpoint(t, name)
	if len(got) != 1 || !got[0].Equal(*r0) {
		t.Fatalf("stream after duplicate write = %+v, want exactly the first record", got)
	}

	// Duplicates already present on disk are rejected when reopening.
	enc2 := reopenCheckpoint(t, name)
	if err := enc2.Encode(testResult(0)); !errors.Is(err, ErrCheckpointDuplicate) {
		t.Fatalf("duplicate write after resume: got %v, want %v", err, ErrCheckpointDuplicate)
	}
	enc2.Close()

	// A stored stream that repeats seq 0 must be rejected.
	var raw []byte
	raw = append(raw, checkpointHeader()...)
	var prev [checkpointDigestSize]byte
	raw = appendRawFrame(t, raw, &prev, testResult(0))
	raw = appendRawFrame(t, raw, &prev, testResult(0))
	stored := writeRawCheckpoint(t, raw)

	rf, err := os.Open(stored)
	if err != nil {
		t.Fatal(err)
	}
	dec := NewCheckpointDecoder(rf)
	var res Result
	if err := dec.Decode(&res); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&res); !errors.Is(err, ErrCheckpointDuplicate) {
		rf.Close()
		t.Fatalf("stored duplicate: got %v, want %v", err, ErrCheckpointDuplicate)
	}
	rf.Close()

	if _, err := OpenCheckpoint(mustOpenRDWR(t, stored)); !errors.Is(err, ErrCheckpointDuplicate) {
		t.Fatalf("OpenCheckpoint on stored duplicate: got %v, want %v", err, ErrCheckpointDuplicate)
	}
}

func TestCheckpointOutOfOrder(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	if err := enc.Encode(testResult(0)); err != nil {
		t.Fatal(err)
	}

	// A gap in the live sequence is rejected without consuming the result.
	if err := enc.Encode(testResult(2)); !errors.Is(err, ErrCheckpointOutOfOrder) {
		t.Fatalf("gap write: got %v, want %v", err, ErrCheckpointOutOfOrder)
	}
	if got := enc.Next(); got != 1 {
		t.Fatalf("Next after gap: got %d, want 1", got)
	}
	if err := enc.Encode(testResult(1)); err != nil {
		t.Fatalf("filling the gap after rejection: %v", err)
	}
	name := f.Name()
	enc.Close()
	f.Close()

	got := decodeCheckpoint(t, name)
	if len(got) != 2 || got[0].Seq != 0 || got[1].Seq != 1 {
		t.Fatalf("stream after reorder recovery = %+v, want seqs [0 1]", got)
	}

	// A stored stream that skips seq 1 must be rejected on resume and decode.
	var raw []byte
	raw = append(raw, checkpointHeader()...)
	var prev [checkpointDigestSize]byte
	raw = appendRawFrame(t, raw, &prev, testResult(0))
	raw = appendRawFrame(t, raw, &prev, testResult(2))
	stored := writeRawCheckpoint(t, raw)

	rf, err := os.Open(stored)
	if err != nil {
		t.Fatal(err)
	}
	dec := NewCheckpointDecoder(rf)
	var res Result
	if err := dec.Decode(&res); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&res); !errors.Is(err, ErrCheckpointOutOfOrder) {
		rf.Close()
		t.Fatalf("stored gap: got %v, want %v", err, ErrCheckpointOutOfOrder)
	}
	rf.Close()

	if _, err := OpenCheckpoint(mustOpenRDWR(t, stored)); !errors.Is(err, ErrCheckpointOutOfOrder) {
		t.Fatalf("OpenCheckpoint on stored gap: got %v, want %v", err, ErrCheckpointOutOfOrder)
	}
}

func TestCheckpointTruncated(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	boundaries := map[int64]bool{int64(checkpointHeaderSize): true}
	for seq := uint64(0); seq < 3; seq++ {
		if err := enc.Encode(testResult(seq)); err != nil {
			t.Fatal(err)
		}
		boundaries[enc.offset] = true
	}
	name := f.Name()
	total := enc.offset
	enc.Close()
	f.Close()

	// Cut points probe the partial header, every frame start and interior,
	// and every confirmed frame boundary.
	cuts := map[int64]bool{
		1: false, int64(checkpointHeaderSize) - 1: false,
		int64(checkpointHeaderSize): true,
	}
	ends := make([]int64, 0, len(boundaries))
	for b := range boundaries {
		ends = append(ends, b)
	}
	sortInt64s(ends)
	for i, end := range ends {
		var start int64 = int64(checkpointHeaderSize)
		if i > 0 {
			start = ends[i-1]
		}
		cuts[end] = true // confirmed boundary
		if start < end {
			cuts[start+1] = false // first bytes of the frame (its header)
			mid := start + (end-start)/2
			cuts[mid] = false   // frame interior
			cuts[end-1] = false // final digest byte missing
		}
	}

	good, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	for size, valid := range cuts {
		if size > total {
			continue
		}
		size, valid := size, valid
		t.Run(fmt.Sprintf("cut=%d", size), func(t *testing.T) {
			restoreFile(t, name, good)
			truncateTo(t, name, size)

			rf, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			dec := NewCheckpointDecoder(rf)
			var records int
			for {
				var res Result
				err := dec.Decode(&res)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					if valid {
						t.Fatalf("decode at boundary %d: %v", size, err)
					}
					if !errors.Is(err, ErrCheckpointTruncated) {
						t.Fatalf("decode at cut %d: got %v, want %v", size, err, ErrCheckpointTruncated)
					}
					break
				}
				records++
			}
			rf.Close()

			wf := mustOpenRDWR(t, name)
			_, err = OpenCheckpoint(wf)
			if valid {
				if err != nil {
					t.Fatalf("OpenCheckpoint at boundary %d: %v", size, err)
				}
			} else if !errors.Is(err, ErrCheckpointTruncated) {
				t.Fatalf("OpenCheckpoint at cut %d: got %v, want %v", size, err, ErrCheckpointTruncated)
			}
			wf.Close()
		})
	}
}

func TestCheckpointCorrupt(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	if err := enc.Encode(testResult(0)); err != nil {
		t.Fatal(err)
	}
	frame1Start := enc.offset
	if err := enc.Encode(testResult(1)); err != nil {
		t.Fatal(err)
	}
	frame1End := enc.offset
	name := f.Name()
	enc.Close()
	f.Close()

	good, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int64{
		frame1Start + 1,                          // tamper seq bytes
		frame1Start + checkpointFrameHdrSize + 3, // tamper payload
		frame1End - 1,                            // tamper digest
		frame1Start + checkpointSeqSize,          // tamper length field
	} {
		offset := offset
		t.Run(fmt.Sprintf("flip@%d", offset), func(t *testing.T) {
			restoreFile(t, name, good)
			flipByte(t, name, offset)

			rf, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			dec := NewCheckpointDecoder(rf)
			var res Result
			if err := dec.Decode(&res); err != nil { // record 0 stays valid
				t.Fatalf("record before corruption: %v", err)
			}
			if err := dec.Decode(&res); !errors.Is(err, ErrCheckpointCorrupt) {
				t.Errorf("tamper at %d: got %v, want %v", offset, err, ErrCheckpointCorrupt)
			}
			rf.Close()

			wf := mustOpenRDWR(t, name)
			if _, err := OpenCheckpoint(wf); !errors.Is(err, ErrCheckpointCorrupt) {
				t.Errorf("OpenCheckpoint tamper at %d: got %v, want %v", offset, err, ErrCheckpointCorrupt)
			}
			wf.Close()
		})
	}
}

func TestCheckpointVersionIncompatible(t *testing.T) {
	t.Parallel()

	// Unknown magic.
	badMagic := writeRawCheckpoint(t, append([]byte("NOT-VEGETA-CHECKPT!!"), 0x01))
	assertVersionRejected(t, badMagic)

	// Right magic but a future version.
	raw := append([]byte{}, checkpointMagic...)
	raw = append(raw, checkpointVersion+1)
	badVersion := writeRawCheckpoint(t, raw)
	assertVersionRejected(t, badVersion)

	// A rejected header must not be modified.
	before := readFileSize(t, badVersion)
	wf := mustOpenRDWR(t, badVersion)
	if _, err := OpenCheckpoint(wf); !errors.Is(err, ErrCheckpointVersion) {
		t.Fatalf("OpenCheckpoint bad version: got %v, want %v", err, ErrCheckpointVersion)
	}
	wf.Close()
	if after := readFileSize(t, badVersion); after != before {
		t.Fatalf("file modified on rejected header: size %d -> %d", before, after)
	}
}

func assertVersionRejected(t *testing.T, name string) {
	t.Helper()
	rf, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewCheckpointDecoder(rf).Decode(&Result{}); !errors.Is(err, ErrCheckpointVersion) {
		rf.Close()
		t.Fatalf("decode bad version: got %v, want %v", err, ErrCheckpointVersion)
	}
	rf.Close()

	wf := mustOpenRDWR(t, name)
	if _, err := OpenCheckpoint(wf); !errors.Is(err, ErrCheckpointVersion) {
		t.Fatalf("OpenCheckpoint bad version: got %v, want %v", err, ErrCheckpointVersion)
	}
	wf.Close()
}

func TestCheckpointConcurrentWrites(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	const (
		workers = 10
		records = 500
	)
	var claimed, committed uint64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				seq := atomic.AddUint64(&claimed, 1) - 1
				if seq >= records {
					return
				}
				r := testResult(seq)
				for {
					switch err := enc.Encode(r); {
					case err == nil:
						atomic.AddUint64(&committed, 1)
						break
					case errors.Is(err, ErrCheckpointOutOfOrder):
						// Another worker still owns an earlier sequence; retry
						// without consuming a different result.
						runtime.Gosched()
						continue
					default:
						t.Errorf("concurrent encode: %v", err)
						return
					}
					break
				}
			}
		}()
	}
	wg.Wait()
	if committed != records {
		t.Fatalf("committed %d records, want %d", committed, records)
	}

	// Every worker races to commit the very next sequence. Exactly one wins;
	// the rest must see a duplicate, never a torn or duplicated frame.
	var duplicates, wins int64
	var dwg sync.WaitGroup
	for i := 0; i < workers; i++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			switch err := enc.Encode(testResult(records)); {
			case err == nil:
				atomic.AddInt64(&wins, 1)
			case errors.Is(err, ErrCheckpointDuplicate):
				atomic.AddInt64(&duplicates, 1)
			default:
				t.Errorf("duplicate race: %v", err)
			}
		}()
	}
	dwg.Wait()
	if wins != 1 || duplicates != workers-1 {
		t.Fatalf("duplicate race: %d wins and %d duplicates, want 1 and %d",
			wins, duplicates, workers-1)
	}

	name := f.Name()
	enc.Close()
	f.Close()

	got := decodeCheckpoint(t, name)
	if len(got) != records+1 {
		t.Fatalf("got %d records, want %d", len(got), records+1)
	}
	for i := range got {
		if want := testResult(uint64(i)); !got[i].Equal(*want) {
			t.Fatalf("record %d mismatch:\ngot:  %+v\nwant: %+v", i, got[i], *want)
		}
	}
}

// errInjectedCheckpoint is a synthetic storage failure for rollback tests.
var errInjectedCheckpoint = errors.New("injected checkpoint storage failure")

// failingCheckpointFile fails the first armed Write after partially writing it.
type failingCheckpointFile struct {
	*os.File
	armed bool
	short bool
	used  bool
}

func (f *failingCheckpointFile) Write(p []byte) (int, error) {
	if f.armed && !f.used {
		f.used = true
		n, err := f.File.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		if f.short {
			return n, nil // short write without an error
		}
		return n, errInjectedCheckpoint
	}
	return f.File.Write(p)
}

func TestCheckpointWriteFailureDoesNotConsumeResult(t *testing.T) {
	t.Parallel()

	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprintf("short=%v", short), func(t *testing.T) {
			f, err := os.CreateTemp("", "vegeta-checkpoint-fail-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())

			ff := &failingCheckpointFile{File: f, short: short}
			enc, err := OpenCheckpoint(ff)
			if err != nil {
				t.Fatal(err)
			}
			headerLen := enc.offset

			// Arm the failure and attempt the first record.
			r0 := testResult(0)
			ff.armed = true
			err = enc.Encode(r0)
			switch {
			case short && !errors.Is(err, io.ErrShortWrite):
				t.Fatalf("short write: got %v, want %v", err, io.ErrShortWrite)
			case !short && !errors.Is(err, errInjectedCheckpoint):
				t.Fatalf("failed write: got %v, want %v", err, errInjectedCheckpoint)
			}

			// State did not advance: the result was neither committed nor
			// consumed, and no partial frame remains on disk.
			if enc.Next() != 0 {
				t.Fatalf("Next after failure: got %d, want 0", enc.Next())
			}
			if enc.offset != headerLen {
				t.Fatalf("offset after failure: got %d, want %d", enc.offset, headerLen)
			}
			if size := readFileSize(t, f.Name()); size != headerLen {
				t.Fatalf("file size after failed write: got %d, want %d", size, headerLen)
			}

			// Retrying the very same result commits it exactly once.
			if err := enc.Encode(r0); err != nil {
				t.Fatalf("retry after failure: %v", err)
			}
			if enc.Next() != 1 {
				t.Fatalf("Next after retry: got %d, want 1", enc.Next())
			}
			enc.Close()
			f.Close()

			got := decodeCheckpoint(t, f.Name())
			if len(got) != 1 {
				t.Fatalf("got %d records after retry, want 1", len(got))
			}
			if !got[0].Equal(*r0) {
				t.Fatalf("retried record mismatch:\ngot:  %+v\nwant: %+v", got[0], *r0)
			}

			// Recovery still continues at seq 1, proving the failed write
			// did not duplicate or skip a sequence number.
			enc2 := reopenCheckpoint(t, f.Name())
			if enc2.Next() != 1 {
				t.Fatalf("Next after reopen: got %d, want 1", enc2.Next())
			}
			enc2.Close()
		})
	}
}

// TestCheckpointReportDoesNotChangeScheduling runs a real, paced attack whose
// results are drained into a checkpoint while reports are generated
// continuously from independent read-only handles. The pacer must emit the
// same number of hits as it would with any other result sink.
func TestCheckpointReportDoesNotChangeScheduling(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	f, err := os.CreateTemp("", "vegeta-checkpoint-sched-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	enc, err := OpenCheckpoint(f)
	if err != nil {
		t.Fatal(err)
	}

	rate := Rate{Freq: 100, Per: time.Second}
	atk := NewAttacker(Workers(1)) // ordered seq delivery for the strict sink
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	res := atk.Attack(tr, rate, time.Second, "scheduling")

	// Report generation reads only; it never feeds back into the attack.
	stop := make(chan struct{})
	var reportWG sync.WaitGroup
	reportWG.Add(1)
	var reports int64
	go func() {
		defer reportWG.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}

			rf, err := os.Open(f.Name())
			if err != nil {
				continue
			}
			dec := NewCheckpointDecoder(rf)
			var m Metrics
			for {
				var r Result
				err := dec.Decode(&r)
				if errors.Is(err, io.EOF) {
					break
				}
				if errors.Is(err, ErrCheckpointTruncated) {
					break // a record is still being appended
				}
				if err != nil {
					t.Errorf("report decode: %v", err)
					break
				}
				m.Add(&r)
			}
			rf.Close()
			m.Close()
			atomic.AddInt64(&reports, 1)
		}
	}()

	var hits uint64
	for r := range res {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode during attack: %v", err)
		}
		hits++
	}
	close(stop)
	reportWG.Wait()
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// The configured pacer must drive the attack even while the sink stores
	// records and independent readers generate reports from the same file.
	if want := uint64(rate.Freq); hits < want*9/10 || hits > want*11/10 {
		t.Fatalf("attack produced %d hits, want ~%d paced; report generation must not alter scheduling",
			hits, want)
	}
	if atomic.LoadInt64(&reports) == 0 {
		t.Fatal("no concurrent reports were generated")
	}

	got := decodeCheckpoint(t, f.Name())
	if len(got) != int(hits) {
		t.Fatalf("checkpoint holds %d records, want %d", len(got), hits)
	}
	for i := range got {
		if got[i].Seq != uint64(i) {
			t.Fatalf("record %d has seq %d, want %d", i, got[i].Seq, i)
		}
	}
}

func TestCheckpointDecoderFor(t *testing.T) {
	t.Parallel()

	enc, f := openTempCheckpoint(t)
	for seq := uint64(0); seq < 3; seq++ {
		if err := enc.Encode(testResult(seq)); err != nil {
			t.Fatal(err)
		}
	}
	name := f.Name()
	enc.Close()
	f.Close()

	rf, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	dec := DecoderFor(rf)
	if dec == nil {
		rf.Close()
		t.Fatal("DecoderFor did not detect the checkpoint format")
	}
	var n int
	for {
		var r Result
		if err := dec.Decode(&r); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			rf.Close()
			t.Fatal(err)
		}
		n++
	}
	rf.Close()
	if n != 3 {
		t.Fatalf("DecoderFor decoded %d records, want 3", n)
	}
}

// --- small file helpers (kept local to avoid touching production code) ---

func mustOpenRDWR(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile(name, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func truncateTo(t *testing.T, name string, size int64) {
	t.Helper()
	f := mustOpenRDWR(t, name)
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// restoreFile rewrites name with the given bytes so each mutation subtest
// starts from the same valid stream.
func restoreFile(t *testing.T, name string, good []byte) {
	t.Helper()
	if err := os.WriteFile(name, good, 0644); err != nil {
		t.Fatal(err)
	}
}

func flipByte(t *testing.T, name string, offset int64) {
	t.Helper()
	f := mustOpenRDWR(t, name)
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		t.Fatal(err)
	}
	b := []byte{0}
	if _, err := io.ReadFull(f, b); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		t.Fatal(err)
	}
	b[0] ^= 0xFF
	if _, err := f.Write(b); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
}

func readFileSize(t *testing.T, name string) int64 {
	t.Helper()
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func sortInt64s(xs []int64) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
