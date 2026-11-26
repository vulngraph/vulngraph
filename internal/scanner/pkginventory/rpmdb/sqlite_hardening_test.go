package rpmdb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRecord_RejectsSerialLengthOverflow(t *testing.T) {
	_, err := parseRecord([]byte{10, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	require.Error(t, err)
}

func FuzzParseRecord(f *testing.F) {
	f.Add([]byte{10, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	f.Add([]byte{2, 13})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseRecord(b) })
}
