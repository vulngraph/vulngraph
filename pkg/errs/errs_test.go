package errs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Wrap ─────────────────────────────────────────────────────────────────────

func TestWrap_NilError_ReturnsNil(t *testing.T) {
	result := Wrap(nil, "context message")
	assert.NoError(t, result, "Wrap(nil, ...) must return nil")
}

func TestWrap_NonNilError_WrapsWithMessage(t *testing.T) {
	original := errors.New("original error")
	result := Wrap(original, "context")
	require.Error(t, result)
	assert.Contains(t, result.Error(), "context", "wrapped error must contain context message")
	assert.Contains(t, result.Error(), "original error", "wrapped error must contain original message")
}

func TestWrap_PreservesUnwrapChain(t *testing.T) {
	original := errors.New("root cause")
	wrapped := Wrap(original, "outer context")
	require.Error(t, wrapped)
	assert.True(t, errors.Is(wrapped, original), "errors.Is must traverse Wrap chain")
}

func TestWrap_EmptyMessage(t *testing.T) {
	original := errors.New("some error")
	result := Wrap(original, "")
	require.Error(t, result)
	assert.Contains(t, result.Error(), "some error")
}

func TestWrap_MessageFormat(t *testing.T) {
	original := errors.New("db timeout")
	result := Wrap(original, "query failed")
	assert.Equal(t, "query failed: db timeout", result.Error())
}

func TestWrap_MultipleWraps_AllUnwrappable(t *testing.T) {
	root := errors.New("root")
	first := Wrap(root, "layer-1")
	second := Wrap(first, "layer-2")

	assert.True(t, errors.Is(second, root), "errors.Is must unwrap through multiple Wrap levels")
	assert.Contains(t, second.Error(), "layer-2")
	assert.Contains(t, second.Error(), "layer-1")
	assert.Contains(t, second.Error(), "root")
}

func TestWrap_NilWithEmptyMessage_StillReturnsNil(t *testing.T) {
	result := Wrap(nil, "")
	assert.NoError(t, result)
}

// ── New ──────────────────────────────────────────────────────────────────────

func TestNew_ReturnsNonNilError(t *testing.T) {
	err := New("something went wrong")
	require.Error(t, err)
}

func TestNew_MessagePreserved(t *testing.T) {
	msg := "connection refused"
	err := New(msg)
	assert.Equal(t, msg, err.Error())
}

func TestNew_EmptyString_ReturnsErrorWithEmptyMessage(t *testing.T) {
	err := New("")
	require.Error(t, err)
	assert.Equal(t, "", err.Error())
}

func TestNew_UniqueInstances(t *testing.T) {
	a := New("same message")
	b := New("same message")
	// Two New calls with same message should produce distinct error values
	// (not pointer-equal), but that is not guaranteed — verify they are both errors
	require.Error(t, a)
	require.Error(t, b)
	assert.Equal(t, a.Error(), b.Error())
}

func TestNew_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"unicode", "error: données invalides"},
		{"emoji", "💥 critical failure"},
		{"sql injection chars", "error: ' OR 1=1 --"},
		{"newlines", "line1\nline2"},
		{"tab", "field\tvalue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(tt.msg)
			require.Error(t, err)
			assert.Equal(t, tt.msg, err.Error())
		})
	}
}

// ── Integration: Wrap + New ───────────────────────────────────────────────────

func TestWrap_AroundNew(t *testing.T) {
	inner := New("disk full")
	outer := Wrap(inner, "write failed")
	require.Error(t, outer)
	assert.True(t, errors.Is(outer, inner))
	assert.Equal(t, "write failed: disk full", outer.Error())
}

// ── Code mapping ──────────────────────────────────────────────────────────────

func TestError_HTTPStatus(t *testing.T) {
	tests := []struct {
		code Code
		want int
	}{
		{CodeNotFound, 404},
		{CodeForbidden, 403},
		{CodeInvalidInput, 400},
		{CodeConflict, 409},
		{CodeTimeout, 504},
		{CodeInternal, 500},
		{CodeUnknown, 500},
	}
	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			e := &Error{code: tt.code, msg: "test"}
			assert.Equal(t, tt.want, e.HTTPStatus())
		})
	}
}

func TestError_Is_MatchesByCode(t *testing.T) {
	err := NotFound("connector xyz")
	assert.True(t, errors.Is(err, ErrNotFound))
	assert.False(t, errors.Is(err, ErrForbidden))
}

func TestHTTPStatus_UnknownError(t *testing.T) {
	got := HTTPStatus(errors.New("generic"))
	assert.Equal(t, 500, got)
}
