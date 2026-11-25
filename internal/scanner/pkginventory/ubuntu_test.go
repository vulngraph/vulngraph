package pkginventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUbuntuLTSDetection covers the suffix rule directly, including the
// boundary that decides it (April of an even year).
func TestUbuntuLTSDetection(t *testing.T) {
	for _, v := range []string{"20.04", "22.04", "24.04", "26.04"} {
		assert.True(t, isUbuntuLTS(v), "%s is an LTS", v)
	}
	for _, v := range []string{"25.10", "23.04", "22.10", "21.04", "", "22", "2022.04", "xx.04"} {
		assert.False(t, isUbuntuLTS(v), "%s is not an LTS", v)
	}
}
