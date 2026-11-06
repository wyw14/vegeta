//go:build gofuzz
// +build gofuzz

package vegeta

import (
	"bytes"
	"io"
)

// FuzzResultsFormatDetection tests result list format detection.
func FuzzResultsFormatDetection(fuzz []byte) int {
	decoder := DecoderFor(bytes.NewReader(fuzz))
	if decoder == nil {
		return 0
	}
	ok := readAllResults(decoder)
	if !ok {
		return 0
	}
	return 1
}

// FuzzGobDecoder tests decoding a gob format result list.
func FuzzGobDecoder(fuzz []byte) int {
	decoder := NewDecoder(bytes.NewReader(fuzz))
	ok := readAllResults(decoder)
	if !ok {
		return 0
	}
	return 1
}

// FuzzCSVDecoder tests decoding a CSV format result list.
func FuzzCSVDecoder(fuzz []byte) int {
	decoder := NewCSVDecoder(bytes.NewReader(fuzz))
	ok := readAllResults(decoder)
	if !ok {
		return 0
	}
	return 1
}

// FuzzJSONDecoder tests decoding a JSON format result list.
func FuzzJSONDecoder(fuzz []byte) int {
	decoder := NewJSONDecoder(bytes.NewReader(fuzz))
	ok := readAllResults(decoder)
	if !ok {
		return 0
	}
	return 1
}

// FuzzCheckpointDecoder tests decoding a checkpoint stream. A malformed
// stream header is rejected; a stream with a valid header must only ever
// yield decoded results or io.EOF (including truncated-tail recovery).
func FuzzCheckpointDecoder(fuzz []byte) int {
	decoder, err := NewCheckpointDecoder(bytes.NewReader(fuzz))
	if err != nil {
		return 0
	}
	return readAllResults(decoder.Decode)
}

func readAllResults(decoder Decoder) (ok bool) {
	for {
		result := &Result{}
		err := decoder.Decode(result)
		if err == io.EOF {
			return true
		} else if err != nil {
			return false
		}
	}
}
