package asset

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Assets are listed newest-first by (last_seen, id); the cursor is that seek key
// (opaque base64 of "<last_seen unixnano>|<id>" — id last so a "|" in
// the id survives SplitN).

// EncodeCursor returns a resume token for the last asset on a page.
func EncodeCursor(a Asset) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strconv.FormatInt(a.LastSeen.UnixNano(), 10) + "|" + a.ID))
}

// decodeCursor parses a token from EncodeCursor, or ErrBadCursor.
func decodeCursor(token string) (lastSeen time.Time, id string, err error) {
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil {
		return time.Time{}, "", ErrBadCursor
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", ErrBadCursor
	}
	ns, e := strconv.ParseInt(parts[0], 10, 64)
	if e != nil {
		return time.Time{}, "", ErrBadCursor
	}
	return time.Unix(0, ns).UTC(), parts[1], nil
}
