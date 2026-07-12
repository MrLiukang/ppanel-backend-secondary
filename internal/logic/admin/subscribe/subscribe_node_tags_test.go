package subscribe

import (
	"reflect"
	"testing"
)

func TestNormalizeSubscribeNodeTagsReturnsEmptySliceForBlankTags(t *testing.T) {
	if got := normalizeSubscribeNodeTags(""); !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("normalizeSubscribeNodeTags(\"\") = %#v, want an empty slice", got)
	}
}
