package correlate

import (
	"encoding/binary"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Private, process-local frames avoid reparsing JSON on every rule replay.
// References keep the original JSON byte charge for context/page admission.
// The encoding is not a durable format or an external input protocol.
func appendStagedSourceFrame(dst []byte, row asset.Asset) []byte {
	dst = append(dst, 1)
	for _, value := range []string{row.ID, row.Name, row.Type, row.AccountID, row.PublicIP, row.PrivateIP, row.Domain} {
		dst = appendFrameString(dst, value)
	}
	dst = appendFrameMap(dst, row.Tags)
	return appendFrameMap(dst, row.Metadata)
}

func appendFrameString(dst []byte, value string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(value)))
	return append(dst, value...)
}

func appendFrameMap(dst []byte, values map[string]string) []byte {
	if values == nil {
		return append(dst, 0)
	}
	dst = binary.AppendUvarint(dst, uint64(len(values))+1)
	for key, value := range values {
		dst = appendFrameString(dst, key)
		dst = appendFrameString(dst, value)
	}
	return dst
}

type stagedFrameReader struct {
	data []byte
	err  error
}

func (r *stagedFrameReader) integer() uint64 {
	if r.err != nil {
		return 0
	}
	value, n := binary.Uvarint(r.data)
	if n <= 0 {
		r.err = fmt.Errorf("invalid staged frame length")
		return 0
	}
	r.data = r.data[n:]
	return value
}

func (r *stagedFrameReader) text() string {
	size := r.integer()
	if r.err != nil {
		return ""
	}
	if size > uint64(len(r.data)) {
		r.err = fmt.Errorf("staged frame string exceeds remaining bytes")
		return ""
	}
	// Conversion owns the bytes; no decoded field pins or aliases the cache.
	value := string(r.data[:size])
	r.data = r.data[size:]
	return value
}

func (r *stagedFrameReader) values() map[string]string {
	count := r.integer()
	if r.err != nil || count == 0 {
		return nil
	}
	count--
	// Every pair requires at least two length bytes. Validate before make.
	if count > uint64(len(r.data))/2 {
		r.err = fmt.Errorf("staged frame map exceeds remaining bytes")
		return nil
	}
	values := make(map[string]string, int(count))
	for range count {
		key, value := r.text(), r.text()
		if r.err != nil {
			return nil
		}
		if _, duplicate := values[key]; duplicate {
			r.err = fmt.Errorf("duplicate staged frame map key")
			return nil
		}
		values[key] = value
	}
	return values
}

func decodeStagedSourceFrame(data []byte, row *asset.Asset) error {
	if len(data) == 0 || data[0] != 1 {
		return fmt.Errorf("invalid staged source frame version")
	}
	r := stagedFrameReader{data: data[1:]}
	*row = asset.Asset{ID: r.text(), Name: r.text(), Type: r.text(), AccountID: r.text(), PublicIP: r.text(), PrivateIP: r.text(), Domain: r.text()}
	row.Tags, row.Metadata = r.values(), r.values()
	if r.err != nil {
		return r.err
	}
	if len(r.data) != 0 {
		return fmt.Errorf("trailing staged frame bytes")
	}
	return nil
}
