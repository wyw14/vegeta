package vegeta

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

// CheckpointVersion is the version of the checkpoint stream format written
// and understood by this package.
const CheckpointVersion uint8 = 1

// CheckpointEncoding selects the inner encoding used for the payload of every
// checkpoint frame. The checkpoint framing is identical for all of them: the
// payload of each frame is a single Result encoded with one of the standard
// vegeta encodings.
type CheckpointEncoding uint8

const (
	// CheckpointGob frames Results with the binary gob encoding.
	CheckpointGob CheckpointEncoding = 1
	// CheckpointJSON frames Results with the JSON encoding.
	CheckpointJSON CheckpointEncoding = 2
	// CheckpointCSV frames Results with the CSV text encoding.
	CheckpointCSV CheckpointEncoding = 3
)

// String returns the name of the inner payload encoding.
func (e CheckpointEncoding) String() string {
	switch e {
	case CheckpointGob:
		return "gob"
	case CheckpointJSON:
		return "json"
	case CheckpointCSV:
		return "csv"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(e))
	}
}

func (e CheckpointEncoding) valid() bool {
	switch e {
	case CheckpointGob, CheckpointJSON, CheckpointCSV:
		return true
	default:
		return false
	}
}

// encode encodes a single Result as a self-contained payload. Every frame
// carries its own encoded type information, so frames remain independently
// decodable, which is what makes truncated stream recovery possible.
func (e CheckpointEncoding) encode(w io.Writer, r *Result) error {
	switch e {
	case CheckpointGob:
		return NewEncoder(w)(r)
	case CheckpointJSON:
		return NewJSONEncoder(w)(r)
	case CheckpointCSV:
		return NewCSVEncoder(w)(r)
	default:
		return fmt.Errorf("%w: %d", ErrCheckpointEncoding, uint8(e))
	}
}

// decode decodes a single Result from a frame payload.
func (e CheckpointEncoding) decode(p []byte, r *Result) error {
	rd := bytes.NewReader(p)
	switch e {
	case CheckpointGob:
		return NewDecoder(rd)(r)
	case CheckpointJSON:
		return NewJSONDecoder(rd)(r)
	case CheckpointCSV:
		return NewCSVDecoder(rd)(r)
	default:
		return fmt.Errorf("%w: %d", ErrCheckpointEncoding, uint8(e))
	}
}

var (
	// ErrCheckpointMagic is returned when a checkpoint stream or trailer does
	// not start with the expected magic marker.
	ErrCheckpointMagic = errors.New("checkpoint: bad magic marker")
	// ErrCheckpointVersion is returned when the stream version is unsupported.
	ErrCheckpointVersion = errors.New("checkpoint: unsupported format version")
	// ErrCheckpointEncoding is returned when the payload encoding is unknown.
	ErrCheckpointEncoding = errors.New("checkpoint: unknown payload encoding")
	// ErrCheckpointSequence is returned when a record duplicates or precedes
	// the sequence number range already seen in the stream.
	ErrCheckpointSequence = errors.New("checkpoint: out of order or duplicate sequence number")
	// ErrCheckpointDigest is returned when a frame or its payload fails its
	// checksum verification.
	ErrCheckpointDigest = errors.New("checkpoint: checksum mismatch")
	// ErrCheckpointTrailer is returned when the stream trailer is present but
	// inconsistent with the frames that preceded it.
	ErrCheckpointTrailer = errors.New("checkpoint: invalid stream trailer")
	// ErrCheckpointClosed is returned when encoding into a closed
	// CheckpointEncoder.
	ErrCheckpointClosed = errors.New("checkpoint: encoder is closed")
)

// On-disk layout (all integers are big endian):
//
//	Stream header, once:
//	  magic[5]  = "VGTCP"
//	  version   = CheckpointVersion
//	  encoding = CheckpointGob | CheckpointJSON | CheckpointCSV
//	  flags     = 0 (reserved)
//
//	Data frame, once per Result:
//	  tag       = frameTag
//	  firstSeq  uint64            // first sequence number in the frame
//	  lastSeq   uint64            // last sequence number in the frame
//	  length    uint32            // payload length
//	  payload   [length]byte      // inner-encoded Result
//	  digest    [32]byte          // SHA-256 of version, seq range, length, payload
//
//	Stream trailer, written by CheckpointEncoder.Close:
//	  marker[8] = "VGTCPEND"
//	  firstSeq  uint64
//	  lastSeq   uint64
//	  count     uint64
//	  digest    [32]byte          // SHA-256 of the frame digests, in order
//
// A missing or partially written final frame/trailer marks the stream as
// truncated: all complete frames before it can still be decoded.
const (
	headerMagic     = "VGTCP"
	trailerMagic    = "VGTCPEND"
	frameTag        = 0x01
	streamHeaderLen = 8
	frameHeaderLen  = 21 // tag + firstSeq + lastSeq + length
	trailerLen      = 64 // marker + firstSeq + lastSeq + count + digest
)

// CheckpointStats summarizes the state of a decoded checkpoint stream.
type CheckpointStats struct {
	// Version is the checkpoint format version read from the stream header.
	Version uint8
	// Encoding is the inner payload encoding read from the stream header.
	Encoding CheckpointEncoding
	// FirstSeq and LastSeq are the inclusive sequence number range of the
	// frames decoded so far. They are zero until the first frame is read.
	FirstSeq uint64
	LastSeq  uint64
	// Count is the number of complete frames decoded so far.
	Count uint64
	// Truncated reports that a partially written trailing frame or trailer
	// was discarded while recovering from a truncated file.
	Truncated bool
	// Complete reports that the stream trailer was present and its sequence
	// range and checksum summary were verified.
	Complete bool
}

// frameDigest computes the per-frame checksum summary.
func frameDigest(version byte, firstSeq, lastSeq uint64, length uint32, payload []byte) [32]byte {
	h := sha256.New()
	var buf [21]byte
	buf[0] = version
	binary.BigEndian.PutUint64(buf[1:9], firstSeq)
	binary.BigEndian.PutUint64(buf[9:17], lastSeq)
	binary.BigEndian.PutUint32(buf[17:21], length)
	_, _ = h.Write(buf[:])
	_, _ = h.Write(payload)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// writeFull writes all of p to w, tolerating short writes.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// CheckpointEncoder wraps one of the standard Result encodings (gob, JSON or
// CSV) with a self-describing checkpoint stream. Every frame carries the
// format version, its sequence number range and a checksum summary, allowing
// readers to recover from truncated output and to reject out of order or
// duplicate records.
//
// The CheckpointEncoder never closes the io.Writer it is given: the caller
// owns the writer's lifecycle. Close only writes the stream trailer; it is
// optional, since a stream without a trailer is still recoverable up to its
// last complete frame.
type CheckpointEncoder struct {
	w      io.Writer
	enc    CheckpointEncoding
	stream hash.Hash

	firstSeq uint64
	lastSeq  uint64
	count    uint64
	have     bool
	closed   bool
}

// NewCheckpointEncoder writes the stream header to w and returns a
// CheckpointEncoder using enc for the frame payloads. If writing the header
// fails, the error is returned and w is left untouched (and open).
func NewCheckpointEncoder(w io.Writer, enc CheckpointEncoding) (*CheckpointEncoder, error) {
	if w == nil {
		return nil, errors.New("checkpoint: nil writer")
	}
	if !enc.valid() {
		return nil, fmt.Errorf("%w: %d", ErrCheckpointEncoding, uint8(enc))
	}

	var hdr [streamHeaderLen]byte
	copy(hdr[:len(headerMagic)], headerMagic)
	hdr[5] = CheckpointVersion
	hdr[6] = byte(enc)
	hdr[7] = 0 // reserved flags
	if err := writeFull(w, hdr[:]); err != nil {
		return nil, err
	}

	return &CheckpointEncoder{w: w, enc: enc, stream: sha256.New()}, nil
}

// Encode writes r in its own checkpoint frame. Records must carry strictly
// increasing Seq values: a duplicate (equal) or out of order (smaller) Seq
// is rejected with an error wrapping ErrCheckpointSequence. Gaps in the
// sequence are allowed. The caller-owned writer is never closed, even when
// encoding fails.
func (e *CheckpointEncoder) Encode(r *Result) error {
	if e.closed {
		return ErrCheckpointClosed
	}
	if e.have && r.Seq <= e.lastSeq {
		return fmt.Errorf("%w: seq %d follows %d", ErrCheckpointSequence, r.Seq, e.lastSeq)
	}

	var payload bytes.Buffer
	if err := e.enc.encode(&payload, r); err != nil {
		return err
	}
	if int64(payload.Len()) > math.MaxUint32 {
		return fmt.Errorf("checkpoint: frame payload too large: %d bytes", payload.Len())
	}

	length := uint32(payload.Len())
	sum := frameDigest(CheckpointVersion, r.Seq, r.Seq, length, payload.Bytes())

	var hdr [frameHeaderLen]byte
	hdr[0] = frameTag
	binary.BigEndian.PutUint64(hdr[1:9], r.Seq)
	binary.BigEndian.PutUint64(hdr[9:17], r.Seq)
	binary.BigEndian.PutUint32(hdr[17:21], length)

	if err := writeFull(e.w, hdr[:]); err != nil {
		return err
	}
	if err := writeFull(e.w, payload.Bytes()); err != nil {
		return err
	}
	if err := writeFull(e.w, sum[:]); err != nil {
		return err
	}

	if !e.have {
		e.firstSeq = r.Seq
		e.have = true
	}
	e.lastSeq = r.Seq
	e.count++
	_, _ = e.stream.Write(sum[:])

	return nil
}

// Close writes the stream trailer with the overall sequence number range and
// the checksum summary of every frame. It is idempotent and never closes the
// underlying writer, which is owned by the caller. A stream that is not
// closed remains readable: the decoder treats the missing trailer as a clean
// end at the last complete frame.
func (e *CheckpointEncoder) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true

	var tr [trailerLen]byte
	copy(tr[:len(trailerMagic)], trailerMagic)
	binary.BigEndian.PutUint64(tr[8:16], e.firstSeq)
	binary.BigEndian.PutUint64(tr[16:24], e.lastSeq)
	binary.BigEndian.PutUint64(tr[24:32], e.count)
	copy(tr[32:], e.stream.Sum(nil))

	return writeFull(e.w, tr[:])
}

// CheckpointDecoder reads checkpoint streams produced by CheckpointEncoder.
// It verifies every frame checksum, enforces a strictly increasing sequence
// number range and transparently skips a partially written trailing frame or
// trailer when the input was truncated.
type CheckpointDecoder struct {
	r       *bufio.Reader
	enc     CheckpointEncoding
	version byte
	stats   CheckpointStats
	stream  hash.Hash
	err     error // sticky terminal state
}

// NewCheckpointDecoder reads and validates the stream header from r. An empty
// reader yields io.EOF.
func NewCheckpointDecoder(r io.Reader) (*CheckpointDecoder, error) {
	if r == nil {
		return nil, errors.New("checkpoint: nil reader")
	}

	d := &CheckpointDecoder{
		r:      bufio.NewReader(r),
		stream: sha256.New(),
	}

	var hdr [streamHeaderLen]byte
	if _, err := io.ReadFull(d.r, hdr[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(hdr[:len(headerMagic)], []byte(headerMagic)) {
		return nil, ErrCheckpointMagic
	}
	if hdr[5] != CheckpointVersion {
		return nil, fmt.Errorf("%w: %d", ErrCheckpointVersion, hdr[5])
	}
	d.version = hdr[5]
	d.enc = CheckpointEncoding(hdr[6])
	if !d.enc.valid() {
		return nil, fmt.Errorf("%w: %d", ErrCheckpointEncoding, uint8(d.enc))
	}

	d.stats.Version = d.version
	d.stats.Encoding = d.enc
	return d, nil
}

// Stats returns the current stream statistics. It is safe to call after
// Decode returns io.EOF.
func (d *CheckpointDecoder) Stats() CheckpointStats { return d.stats }

// Decode reads the next complete frame into r. It returns io.EOF when no more
// complete frames are available. If the file ended with a partial frame or
// trailer, io.EOF is returned as well and Stats().Truncated reports the
// discarded tail. Corruption anywhere before the tail (bad checksum, wrong
// ordering, invalid trailer) yields a non-EOF error wrapping one of the
// ErrCheckpoint* sentinels.
func (d *CheckpointDecoder) Decode(r *Result) error {
	if d.err != nil {
		return d.err
	}

	tag, err := d.r.ReadByte()
	if err == io.EOF {
		// Ended exactly on a frame boundary without a trailer.
		d.err = io.EOF
		return io.EOF
	} else if err != nil {
		return d.fail(err)
	}

	switch {
	case tag == frameTag:
		return d.readFrame(r)
	case tag == trailerMagic[0]:
		if err := d.readTrailer(); err != nil {
			d.err = err
			return err
		}
		d.err = io.EOF
		return io.EOF
	default:
		return d.fail(fmt.Errorf("%w: unexpected frame tag %#x", ErrCheckpointMagic, tag))
	}
}

func (d *CheckpointDecoder) readFrame(r *Result) error {
	var hdr [frameHeaderLen - 1]byte
	if _, err := io.ReadFull(d.r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return d.truncated()
		}
		return d.fail(err)
	}

	firstSeq := binary.BigEndian.Uint64(hdr[0:8])
	lastSeq := binary.BigEndian.Uint64(hdr[8:16])
	length := binary.BigEndian.Uint32(hdr[16:20])

	// Read incrementally: a corrupted length field may claim a huge payload
	// while the stream is nearly over, so pre-allocating it could exhaust
	// memory. io.CopyN only grows the buffer with the bytes actually read.
	var payload bytes.Buffer
	if _, err := io.CopyN(&payload, d.r, int64(length)); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return d.truncated()
		}
		return d.fail(err)
	}

	var sum [sha256.Size]byte
	if _, err := io.ReadFull(d.r, sum[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return d.truncated()
		}
		return d.fail(err)
	}

	want := frameDigest(d.version, firstSeq, lastSeq, length, payload.Bytes())
	if sum != want {
		// A bad frame at the very end of the file is indistinguishable from a
		// frame whose tail was torn during writing, so it is treated as
		// truncation. A bad frame followed by more data is real corruption.
		if _, err := d.r.Peek(1); errors.Is(err, io.EOF) {
			return d.truncated()
		}
		return d.fail(fmt.Errorf("%w: frame starting at seq %d", ErrCheckpointDigest, firstSeq))
	}

	// Version 1 frames always hold a single record, so the range is exact.
	if firstSeq != lastSeq {
		return d.fail(fmt.Errorf("%w: frame range [%d, %d] is not a single record",
			ErrCheckpointSequence, firstSeq, lastSeq))
	}
	if d.stats.Count > 0 && firstSeq <= d.stats.LastSeq {
		return d.fail(fmt.Errorf("%w: seq %d follows %d",
			ErrCheckpointSequence, firstSeq, d.stats.LastSeq))
	}

	if err := d.enc.decode(payload.Bytes(), r); err != nil {
		return d.fail(err)
	}
	if r.Seq != firstSeq {
		return d.fail(fmt.Errorf("%w: frame labeled seq %d but payload carries seq %d",
			ErrCheckpointDigest, firstSeq, r.Seq))
	}

	if d.stats.Count == 0 {
		d.stats.FirstSeq = firstSeq
	}
	d.stats.LastSeq = lastSeq
	d.stats.Count++
	_, _ = d.stream.Write(sum[:])

	return nil
}

func (d *CheckpointDecoder) readTrailer() error {
	var marker [len(trailerMagic)]byte
	marker[0] = trailerMagic[0]
	if _, err := io.ReadFull(d.r, marker[1:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return d.trailerTruncated()
		}
		return err
	}
	if !bytes.Equal(marker[:], []byte(trailerMagic)) {
		return fmt.Errorf("%w: bad marker", ErrCheckpointTrailer)
	}

	var body [24]byte // firstSeq + lastSeq + count
	if _, err := io.ReadFull(d.r, body[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return d.trailerTruncated()
		}
		return err
	}

	var sum [sha256.Size]byte
	if _, err := io.ReadFull(d.r, sum[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return d.trailerTruncated()
		}
		return err
	}

	firstSeq := binary.BigEndian.Uint64(body[0:8])
	lastSeq := binary.BigEndian.Uint64(body[8:16])
	count := binary.BigEndian.Uint64(body[16:24])

	switch {
	case count != d.stats.Count:
		return fmt.Errorf("%w: count %d does not match %d frames", ErrCheckpointTrailer, count, d.stats.Count)
	case count == 0 && (firstSeq != 0 || lastSeq != 0):
		return fmt.Errorf("%w: empty stream with non-zero range [%d, %d]",
			ErrCheckpointTrailer, firstSeq, lastSeq)
	case count > 0 && (firstSeq != d.stats.FirstSeq || lastSeq != d.stats.LastSeq):
		return fmt.Errorf("%w: range [%d, %d] does not match frames [%d, %d]",
			ErrCheckpointTrailer, firstSeq, lastSeq, d.stats.FirstSeq, d.stats.LastSeq)
	}

	if !bytes.Equal(sum[:], d.stream.Sum(nil)) {
		return fmt.Errorf("%w: checksum summary", ErrCheckpointTrailer)
	}

	d.stats.Complete = true
	return nil
}

// trailerTruncated marks a partially written trailer as discarded. Records
// decoded before it remain valid.
func (d *CheckpointDecoder) trailerTruncated() error {
	d.stats.Truncated = true
	d.err = io.EOF
	return io.EOF
}

func (d *CheckpointDecoder) truncated() error {
	d.stats.Truncated = true
	d.err = io.EOF
	return io.EOF
}

func (d *CheckpointDecoder) fail(err error) error {
	d.err = err
	return err
}

// checkpointDecoderFactory adapts NewCheckpointDecoder to the DecoderFactory
// signature used by DecoderFor. Construction errors are deferred to the first
// Decode call so that format probing can try the next factory.
func checkpointDecoderFactory(r io.Reader) Decoder {
	d, err := NewCheckpointDecoder(r)
	if err != nil {
		return func(*Result) error { return err }
	}
	return d.Decode
}
