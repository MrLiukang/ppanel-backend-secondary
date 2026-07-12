package tool

import (
	"testing"
)

func TestGenerateCipher(t *testing.T) {
	pwd := GenerateCipher("", 16)
	t.Logf("pwd: %s", pwd)
	t.Logf("pwd length: %d", len(pwd))
}
