package vegeta

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"io"
	"sync"
)

// This file implements a streaming, resumable and integrity-checked format
// for attack Result records: the checkpoint format.
//
// Every record is keyed by its result sequence number (Result.Seq) and
// carries a checksum digest. Records form a hash chain, so truncation,
// corruption and any reordering of the stream are detected when a checkpoint
// is reopened.
//
// On-disk layout, all integers are big-endian:
//
//	stream  = header *frame
//	header  = checkpointMagic checkpointVersion(1 byte)
//	frame   = seq(uint64) length(uint32) payload(length bytes) digest(32 bytes)
//	payload = gob encoded Result
//	digest  = SHA-256(prevDigest || seq || length || payload)
//
// The digest of the first record is chained from a 32 zero bytes seed.
//
// A zero byte file is a valid, empty checkpoint: the header is written
// lazily when it is first opened for writing. A stream that ends on a frame
// boundary is complete; a stream that ends in the middle of a frame has been
// truncated and is rejected.

const (
	checkpointMagicString = "VEGETA-CHECKPOINT\n"
	checkpointVersion     = uint8(1)

	checkpointHeaderSize   = len(checkpointMagicString) + 1
	checkpointSeqSize      = 8
	checkpointLengthSize   = 4
	checkpointFrameHdrSize = checkpointSeqSize + checkpointLengthSize
	checkpointDigestSize   = sha256.Size

	// checkpointMaxPayload bounds the memory allocated for a single frame
	// payload while decoding. It guards against corrupt length fields and is
	// large enough for any realistic response body capture.
	checkpointMaxPayload = 1 << 30 // 1 GiB
)

var (
	checkpointMagic   = []byte(checkpointMagicString)
	checkpointZeroDgt [checkpointDigestSize]byte
)

// Sentinel errors returned when a checkpoint is read or written. Callers can
// compare with errors.Is.
var (
	// ErrCheckpointVersion is returned when the stream does not start with
	// the checkpoint magic or carries an unsupported format version.
	ErrCheckpointVersion = errors.New("vegeta: incompatible checkpoint format or version")
	// ErrCheckpointTruncated is returned when the stream ends with a partial
	// header or frame.
	ErrCheckpointTruncated = errors.New("vegeta: checkpoint stream is truncated")
	// ErrCheckpointCorrupt is returned when a record payload or checksum
	// digest fails verification.
	ErrCheckpointCorrupt = errors.New("vegeta: checkpoint record is corrupt")
	// ErrCheckpointOutOfOrder is returned when a record sequence number is
	// greater than the next expected one, i.e. a preceding record is
	// missing.
	ErrCheckpointOutOfOrder = errors.New("vegeta: checkpoint sequence number is out of order")
	// ErrCheckpointDuplicate is returned when a record with a sequence number
	// that was already committed is written or found in the stream.
	ErrCheckpointDuplicate = errors.New("vegeta: checkpoint sequence number was already committed")
	// ErrCheckpointClosed is returned by Encode after the encoder was Closed.
	ErrCheckpointClosed = errors.New("vegeta: checkpoint encoder is closed")
)

// CheckpointFile is the storage interface required by OpenCheckpoint. It is
// satisfied by *os.File. A checkpoint is validated by reading it from the
// beginning, reopened for append by seeking to its end and rolled back after
// a failed write by truncating it back to the last committed offset.
type CheckpointFile interface {
	io.Reader
	io.Writer
	io.Seeker
	Truncate(size int64) error
}

// A CheckpointEncoder writes Result records to a checkpoint stream in Result
// sequence number order. It is safe for concurrent use: concurrent Encode
// calls are serialized, each sequence number is committed at most once and a
// failed write never advances the encoder state, so the very same Result can
// be retried without being duplicated or skipped.
//
// CheckpointEncoder satisfies the Encoder adapter type through its Encode
// method, so it plugs into the same result drain loop as any other encoder
// without affecting attack scheduling.
type CheckpointEncoder struct {
	f CheckpointFile

	mu     sync.Mutex
	next   uint64
	prev   [checkpointDigestSize]byte
	offset int64
	closed bool
}

// Compile-time assertion that a CheckpointEncoder is a plug-in Encoder.
var _ Encoder = (*CheckpointEncoder)(nil).Encode

// OpenCheckpoint opens f as a checkpoint stream for resumable writing.
//
// If f is empty, a new stream is initialized with the current format
// version. Otherwise the whole existing stream is validated before this
// method returns: an incompatible version, a truncated trailing record, a
// corrupt checksum or any gap or duplicate sequence number causes the
// corresponding typed error and f is left unmodified.
//
// After successful validation, new records are appended right after the last
// confirmed one and the encoder expects their sequence numbers to continue at
// Next.
func OpenCheckpoint(f CheckpointFile) (*CheckpointEncoder, error) {
	c := &CheckpointEncoder{f: f}

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		if err := c.writeHeader(); err != nil {
			return nil, err
		}
		return c, nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	next, prev, err := scanCheckpoint(f)
	if err != nil {
		return nil, err
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	c.next = next
	c.prev = prev
	c.offset = offset
	return c, nil
}

// Next returns the sequence number the encoder expects on the next Encode
// call, i.e. one past the last confirmed sequence number.
func (c *CheckpointEncoder) Next() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next
}

// LastSeq returns the last confirmed sequence number and true. It returns
// false when no record has been committed yet.
func (c *CheckpointEncoder) LastSeq() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next == 0 {
		return 0, false
	}
	return c.next - 1, true
}

// Encode commits r as the next checkpoint record.
//
// r.Seq must equal Next. A smaller sequence number returns
// ErrCheckpointDuplicate and a greater one ErrCheckpointOutOfOrder; in both
// cases the stream is left untouched. The frame is fully assembled in memory
// and appended atomically: if the underlying write fails or is short, the
// file is rolled back to the previous committed boundary and the encoder
// state is unchanged, so retrying the same Result does not consume it twice.
func (c *CheckpointEncoder) Encode(r *Result) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrCheckpointClosed
	}

	switch {
	case r.Seq < c.next:
		return ErrCheckpointDuplicate
	case r.Seq > c.next:
		return ErrCheckpointOutOfOrder
	}

	var payload bytes.Buffer
	if err := gob.NewEncoder(&payload).Encode(r); err != nil {
		// Nothing has been written yet: the failed Result is neither
		// committed nor consumed.
		return err
	}

	var hdr [checkpointFrameHdrSize]byte
	binary.BigEndian.PutUint64(hdr[:checkpointSeqSize], r.Seq)
	binary.BigEndian.PutUint32(hdr[checkpointSeqSize:], uint32(payload.Len()))
	dgt := checkpointDigest(c.prev, r.Seq, hdr[checkpointSeqSize:], payload.Bytes())
	frame := encodeCheckpointFrame(hdr, payload.Bytes(), dgt)

	if _, err := c.f.Seek(c.offset, io.SeekStart); err != nil {
		return err
	}

	n, err := c.f.Write(frame)
	if err != nil || n != len(frame) {
		// Restore the last committed boundary so no partial frame remains
		// and no sequence number is lost or duplicated.
		_, _ = c.f.Seek(c.offset, io.SeekStart)
		_ = c.f.Truncate(c.offset)
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}

	c.prev = dgt
	c.offset += int64(n)
	c.next++
	return nil
}

// Close flushes any buffered data to stable storage when the underlying file
// supports it. It does not close the underlying file, which remains owned by
// the caller. It is safe to call Close multiple times.
func (c *CheckpointEncoder) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if syncer, ok := c.f.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}
	return nil
}

func (c *CheckpointEncoder) writeHeader() error {
	if _, err := c.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	header := make([]byte, 0, checkpointHeaderSize)
	header = append(header, checkpointMagic...)
	header = append(header, checkpointVersion)
	n, err := c.f.Write(header)
	if err != nil || n != len(header) {
		_, _ = c.f.Seek(0, io.SeekStart)
		_ = c.f.Truncate(0)
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	c.offset = int64(n)
	return nil
}

// encodeCheckpointFrame builds the on-disk frame for a record.
func encodeCheckpointFrame(hdr [checkpointFrameHdrSize]byte, payload []byte, dgt [checkpointDigestSize]byte) []byte {
	frame := make([]byte, 0, checkpointFrameHdrSize+len(payload)+checkpointDigestSize)
	frame = append(frame, hdr[:]...)
	frame = append(frame, payload...)
	frame = append(frame, dgt[:]...)
	return frame
}

// checkpointDigest computes the chained checksum digest of a record.
func checkpointDigest(prev [checkpointDigestSize]byte, seq uint64, length, payload []byte) [checkpointDigestSize]byte {
	h := sha256.New()
	h.Write(prev[:])
	var seqb [checkpointSeqSize]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	h.Write(seqb[:])
	h.Write(length)
	h.Write(payload)
	var dgt [checkpointDigestSize]byte
	copy(dgt[:], h.Sum(nil))
	return dgt
}

// scanCheckpoint fully validates a non-empty checkpoint stream read from its
// beginning and returns the next expected sequence number and the last record
// digest. A clean end of stream on a frame boundary is not an error.
func scanCheckpoint(r io.Reader) (uint64, [checkpointDigestSize]byte, error) {
	cr := checkpointReader{r: r}
	for {
		var res Result
		switch err := cr.read(&res); {
		case err == nil:
			continue
		case errors.Is(err, io.EOF):
			return cr.next, cr.prev, nil
		default:
			return 0, checkpointZeroDgt, err
		}
	}
}

// checkpointReader is a strict streaming decoder for one checkpoint stream.
type checkpointReader struct {
	r          io.Reader
	next       uint64
	prev       [checkpointDigestSize]byte
	hdrChecked bool
}

// readHeader validates the stream header. A zero byte stream is a valid empty
// checkpoint and yields io.EOF on the first record read instead.
func (cr *checkpointReader) readHeader() error {
	header := make([]byte, checkpointHeaderSize)
	_, err := io.ReadFull(cr.r, header)
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		return io.EOF // empty stream
	case errors.Is(err, io.ErrUnexpectedEOF):
		return ErrCheckpointTruncated
	default:
		return err
	}

	if !bytes.Equal(header[:len(checkpointMagic)], checkpointMagic) {
		return ErrCheckpointVersion
	}
	if version := header[len(checkpointMagic)]; version != checkpointVersion {
		return ErrCheckpointVersion
	}
	return nil
}

// read decodes and validates the next record. It returns io.EOF when the
// stream ends cleanly on a frame boundary.
func (cr *checkpointReader) read(out *Result) error {
	if !cr.hdrChecked {
		if err := cr.readHeader(); err != nil {
			return err
		}
		cr.hdrChecked = true
	}

	var hdr [checkpointFrameHdrSize]byte
	if _, err := io.ReadFull(cr.r, hdr[:]); err != nil {
		// ReadFull returns EOF only with zero bytes read: a clean frame
		// boundary. Any partial header read is truncation.
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF):
			return ErrCheckpointTruncated
		case errors.Is(err, io.EOF):
			return io.EOF
		default:
			return err
		}
	}

	seq := binary.BigEndian.Uint64(hdr[:checkpointSeqSize])
	length := binary.BigEndian.Uint32(hdr[checkpointSeqSize:])
	if uint64(length) > checkpointMaxPayload {
		return ErrCheckpointCorrupt
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(cr.r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrCheckpointTruncated
		}
		return err
	}

	var dgt [checkpointDigestSize]byte
	if _, err := io.ReadFull(cr.r, dgt[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrCheckpointTruncated
		}
		return err
	}

	want := checkpointDigest(cr.prev, seq, hdr[checkpointSeqSize:], payload)
	if subtle.ConstantTimeCompare(dgt[:], want[:]) != 1 {
		return ErrCheckpointCorrupt
	}

	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(out); err != nil {
		return ErrCheckpointCorrupt
	}
	if out.Seq != seq {
		return ErrCheckpointCorrupt
	}

	switch {
	case seq < cr.next:
		return ErrCheckpointDuplicate
	case seq > cr.next:
		return ErrCheckpointOutOfOrder
	}

	cr.prev = dgt
	cr.next++
	return nil
}

// NewCheckpointDecoder returns a Decoder for the checkpoint stream format. It
// validates the version header and every record's ordering and checksum
// digest while decoding. A partially written trailing frame, as can be
// observed while an attack is still appending to the file, yields
// ErrCheckpointTruncated; all preceding records have already been delivered.
func NewCheckpointDecoder(r io.Reader) Decoder {
	cr := &checkpointReader{r: r}
	return func(out *Result) error { return cr.read(out) }
}
