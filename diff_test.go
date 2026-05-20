package merkleforest

import (
	"testing"
)

func TestDiff_Identical(t *testing.T) {
	f := Build(map[string][]Hash{
		"a": {h("1"), h("2")},
		"b": {h("3")},
	})
	added, removed, changed := Diff(f, f)
	if len(added) != 0 || len(removed) != 0 || len(changed) != 0 {
		t.Errorf("identical forests should have no diff")
	}
}

func TestDiff_Added(t *testing.T) {
	old := Build(map[string][]Hash{
		"a": {h("1")},
	})
	new := Build(map[string][]Hash{
		"a": {h("1")},
		"b": {h("2")},
	})
	added, removed, changed := Diff(old, new)
	if len(added) != 1 || added[0] != "b" {
		t.Errorf("expected 'b' added, got %v", added)
	}
	if len(removed) != 0 || len(changed) != 0 {
		t.Errorf("expected no removed/changed")
	}
}

func TestDiff_Removed(t *testing.T) {
	old := Build(map[string][]Hash{
		"a": {h("1")},
		"b": {h("2")},
	})
	new := Build(map[string][]Hash{
		"a": {h("1")},
	})
	added, removed, changed := Diff(old, new)
	if len(removed) != 1 || removed[0] != "b" {
		t.Errorf("expected 'b' removed, got %v", removed)
	}
	if len(added) != 0 || len(changed) != 0 {
		t.Errorf("expected no added/changed")
	}
}

func TestDiff_Changed(t *testing.T) {
	old := Build(map[string][]Hash{
		"a": {h("1"), h("2")},
		"b": {h("3")},
	})
	new := Build(map[string][]Hash{
		"a": {h("1"), h("99")}, // changed
		"b": {h("3")},          // unchanged
	})
	added, removed, changed := Diff(old, new)
	if len(changed) != 1 || changed[0] != "a" {
		t.Errorf("expected 'a' changed, got %v", changed)
	}
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("expected no added/removed")
	}
}

func TestDiff_NilForests(t *testing.T) {
	f := Build(map[string][]Hash{"a": {h("1")}})

	added, _, _ := Diff(nil, f)
	if len(added) != 1 {
		t.Errorf("nil old should show all as added")
	}

	_, removed, _ := Diff(f, nil)
	if len(removed) != 1 {
		t.Errorf("nil new should show all as removed")
	}
}
