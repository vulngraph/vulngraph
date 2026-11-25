package finding

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrBadCursor is returned for a malformed pagination cursor or one whose sort
// mode doesn't match the requested sort. Handlers map it to 400.
var ErrBadCursor = errors.New("finding: invalid cursor")

// keysetCursor is the position of the last finding on a page — the seek key a
// keyset-paginated List resumes from. It carries the row's sort value
// and id, plus which sort it belongs to so it can't be applied across sorts.
type keysetCursor struct {
	byScore bool
	score   uint8
	ts      time.Time
	id      string
}

// EncodeCursor returns an opaque resume token for the last finding on a page.
// byScore must match the List sort the cursor will be used with (score vs
// detected_at), and is recorded in the token so decoding can reject a mismatch.
func EncodeCursor(f Finding, byScore bool) string {
	mode, sortval := "d", strconv.FormatInt(f.DetectedAt.UnixNano(), 10)
	if byScore {
		mode, sortval = "s", strconv.Itoa(int(f.Score))
	}
	// id last so SplitN(_, 3) tolerates a "|" in the id.
	return base64.RawURLEncoding.EncodeToString([]byte(mode + "|" + sortval + "|" + f.ID))
}

// decodeCursor parses a token from EncodeCursor. It returns ErrBadCursor for a
// malformed token or one whose sort mode doesn't match byScore.
func decodeCursor(token string, byScore bool) (keysetCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return keysetCursor{}, ErrBadCursor
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return keysetCursor{}, ErrBadCursor
	}
	mode, sortval, id := parts[0], parts[1], parts[2]
	c := keysetCursor{byScore: byScore, id: id}
	switch {
	case mode == "s" && byScore:
		n, err := strconv.Atoi(sortval)
		if err != nil || n < 0 || n > 255 {
			return keysetCursor{}, ErrBadCursor
		}
		c.score = uint8(n)
	case mode == "d" && !byScore:
		ns, err := strconv.ParseInt(sortval, 10, 64)
		if err != nil {
			return keysetCursor{}, ErrBadCursor
		}
		c.ts = time.Unix(0, ns).UTC()
	default:
		return keysetCursor{}, ErrBadCursor // sort mode mismatch
	}
	return c, nil
}

// EncodeStaleCursor returns an opaque resume token for the last finding on a
// StaleFirst-sorted page (enriched_at ascending — see Filter.StaleFirst).
// Kept separate from EncodeCursor's byScore switch since StaleFirst is a third,
// unrelated sort with its own seek key.
func EncodeStaleCursor(f Finding) string {
	sortval := strconv.FormatInt(f.EnrichedAt.UnixNano(), 10)
	return base64.RawURLEncoding.EncodeToString([]byte("e|" + sortval + "|" + f.ID))
}

// decodeStaleCursor parses a token from EncodeStaleCursor. Returns ErrBadCursor
// for a malformed token or one from a different sort mode.
func decodeStaleCursor(token string) (keysetCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return keysetCursor{}, ErrBadCursor
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 || parts[0] != "e" {
		return keysetCursor{}, ErrBadCursor
	}
	ns, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return keysetCursor{}, ErrBadCursor
	}
	return keysetCursor{ts: time.Unix(0, ns).UTC(), id: parts[2]}, nil
}
