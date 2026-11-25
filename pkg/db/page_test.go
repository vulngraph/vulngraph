package db_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulngraph/vulngraph/pkg/db"
)

// ── ListParams.Clamp ──────────────────────────────────────────────────────────

func TestClamp_DefaultsToFiftyWhenZero(t *testing.T) {
	p := db.ListParams{}
	p.Clamp(500)
	assert.Equal(t, 50, p.Limit)
}

func TestClamp_DefaultsToFiftyWhenNegative(t *testing.T) {
	p := db.ListParams{Limit: -10}
	p.Clamp(500)
	assert.Equal(t, 50, p.Limit)
}

func TestClamp_CapsAtMaxLimit(t *testing.T) {
	p := db.ListParams{Limit: 9999}
	p.Clamp(200)
	assert.Equal(t, 200, p.Limit)
}

func TestClamp_PreservesValidLimit(t *testing.T) {
	p := db.ListParams{Limit: 25}
	p.Clamp(100)
	assert.Equal(t, 25, p.Limit)
}

func TestClamp_ZeroMaxDefaultsToThousand(t *testing.T) {
	p := db.ListParams{Limit: 9999}
	p.Clamp(0)
	assert.Equal(t, 1000, p.Limit)
}

// ── NewPage ───────────────────────────────────────────────────────────────────

func TestNewPage_HasMoreTrueWhenNotLastPage(t *testing.T) {
	page := db.NewPage([]string{"a", "b"}, 10, 2, 0)
	assert.True(t, page.HasMore)
	assert.Equal(t, 10, page.Total)
	assert.Equal(t, 2, page.Limit)
	assert.Equal(t, 0, page.Offset)
}

func TestNewPage_HasMoreFalseOnLastPage(t *testing.T) {
	page := db.NewPage([]string{"i", "j"}, 10, 2, 8)
	assert.False(t, page.HasMore)
}

func TestNewPage_EmptyItemsNeverNil(t *testing.T) {
	page := db.NewPage[string](nil, 0, 50, 0)
	assert.NotNil(t, page.Items)
	assert.Len(t, page.Items, 0)
}

func TestNewPage_SinglePageExact(t *testing.T) {
	items := []int{1, 2, 3}
	page := db.NewPage(items, 3, 10, 0)
	assert.False(t, page.HasMore)
	assert.Equal(t, 3, len(page.Items))
}

// ── CHIn ─────────────────────────────────────────────────────────────────────

func TestCHIn_SingleValue(t *testing.T) {
	ph, args := db.CHIn([]string{"foo"})
	assert.Equal(t, "?", ph)
	assert.Equal(t, []any{"foo"}, args)
}

func TestCHIn_MultipleValues(t *testing.T) {
	ph, args := db.CHIn([]string{"a", "b", "c"})
	assert.Equal(t, "?, ?, ?", ph)
	assert.Len(t, args, 3)
}

func TestCHIn_EmptySlice(t *testing.T) {
	ph, args := db.CHIn([]string{})
	assert.Equal(t, "", ph)
	assert.Len(t, args, 0)
}

func TestCHIn_IntSlice(t *testing.T) {
	ph, args := db.CHIn([]int{10, 20})
	assert.Equal(t, "?, ?", ph)
	assert.Equal(t, []any{10, 20}, args)
}

// ── PGIn ─────────────────────────────────────────────────────────────────────

func TestPGIn_StartsAtOne(t *testing.T) {
	ph, args := db.PGIn([]string{"x", "y"}, 1)
	assert.Equal(t, "$1, $2", ph)
	assert.Equal(t, []any{"x", "y"}, args)
}

func TestPGIn_OffsetStartN(t *testing.T) {
	ph, args := db.PGIn([]string{"a", "b"}, 3)
	assert.Equal(t, "$3, $4", ph)
	assert.Equal(t, []any{"a", "b"}, args)
}

func TestPGIn_SingleValue(t *testing.T) {
	ph, args := db.PGIn([]int{42}, 1)
	assert.Equal(t, "$1", ph)
	assert.Equal(t, []any{42}, args)
}

func TestPGIn_EmptySlice(t *testing.T) {
	ph, args := db.PGIn([]string{}, 1)
	assert.Equal(t, "", ph)
	assert.Len(t, args, 0)
}
