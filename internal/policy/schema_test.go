package policy

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// The policy tables name GitHub's types and fields. A schema refresh that
// renames or drops one would leave a rule that silently matches nothing, so
// every name must still be in the embedded schema.
func TestTablesMatchSchema(t *testing.T) {
	s, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	hasField := func(typ, field string) bool {
		d := s.Types[typ]
		return d != nil && d.Fields.ForName(field) != nil
	}
	for _, e := range slices.Sorted(maps.Keys(sameRepo)) {
		typ, field, _ := strings.Cut(e, ".")
		if !hasField(typ, field) {
			t.Errorf("sameRepo names %s, which the schema lacks", e)
		}
	}
	for _, e := range slices.Sorted(maps.Keys(deniedFields)) {
		typ, field, _ := strings.Cut(e, ".")
		if !hasField(typ, field) {
			t.Errorf("deniedFields names %s, which the schema lacks", e)
		}
	}
	for name, m := range mutations {
		f := s.Mutation.Fields.ForName(name)
		if f == nil {
			t.Errorf("mutation %s isn't in the schema", name)
			continue
		}
		arg := f.Arguments.ForName("input")
		if arg == nil {
			t.Errorf("mutation %s takes no input", name)
			continue
		}
		in := s.Types[arg.Type.Name()]
		names := slices.Concat(m.fields, slices.Collect(maps.Keys(m.opFields)))
		for _, b := range m.binds {
			names = append(names, b.field)
			for _, typ := range b.types {
				if s.Types[typ] == nil {
					t.Errorf("mutation %s binds %s to type %s, which the schema lacks", name, b.field, typ)
				}
			}
		}
		for _, field := range names {
			if in.Fields.ForName(field) == nil {
				t.Errorf("mutation %s names input field %s, which %s lacks", name, field, in.Name)
			}
		}
	}
}
