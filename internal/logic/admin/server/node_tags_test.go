package server

import (
	"reflect"
	"testing"
)

func TestNormalizeNodeTagsReturnsEmptySliceForBlankTags(t *testing.T) {
	if got := normalizeNodeTags(""); !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("normalizeNodeTags(\"\") = %#v, want an empty slice", got)
	}
}
