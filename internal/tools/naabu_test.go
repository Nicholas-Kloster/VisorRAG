package tools

import (
	"reflect"
	"sort"
	"testing"
)

// TestDefaultRegistryLineup pins the NuClide default tool set. Anyone
// adding a probe must consciously update this assertion — guards against
// silently re-introducing the deprecated PD wrappers (httpx/nuclei/asnmap/
// naabu) that were dropped after 7 live runs surfaced their hygiene
// problems on real targets.
func TestDefaultRegistryLineup(t *testing.T) {
	t.Parallel()
	r := NewRegistry(nil) // exec=nil is fine; we only inspect names
	got := r.Names()
	sort.Strings(got)
	want := []string{"aimap", "bare", "menlohunt", "visorgraph"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default registry tools = %v, want %v", got, want)
	}
}


func TestNaabuPortFlag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty defaults to top-100", "", []string{"-top-ports", "100"}},
		{"bare 100 → top-100", "100", []string{"-top-ports", "100"}},
		{"top-100 alias", "top-100", []string{"-top-ports", "100"}},
		{"bare 1000 → top-1000", "1000", []string{"-top-ports", "1000"}},
		{"top-1000 alias", "top-1000", []string{"-top-ports", "1000"}},
		{"full preset", "full", []string{"-top-ports", "full"}},
		{"top-full alias", "top-full", []string{"-top-ports", "full"}},
		{"explicit list", "80,443", []string{"-port", "80,443"}},
		{"explicit range", "1-1000", []string{"-port", "1-1000"}},
		{"hybrid", "22,80,443,8000-9000", []string{"-port", "22,80,443,8000-9000"}},
		// The bug from run #6: model emitted top:10. Old wrapper passed it to
		// -top-ports 10 → naabu rejected. New behavior: numeric != 100/1000
		// falls through to -port, which naabu accepts as a single-port spec.
		{"arbitrary number falls to -port", "10", []string{"-port", "10"}},
		// Whitespace + case folding sanity.
		{"whitespace tolerated", "  TOP-100  ", []string{"-top-ports", "100"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := naabuPortFlag(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("naabuPortFlag(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
