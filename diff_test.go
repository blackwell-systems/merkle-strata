package merklestrata

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

func TestDiffWithOptions_Filter(t *testing.T) {
	old := Build(map[string][]Hash{
		"a": {h("1")},
		"b": {h("2")},
		"c": {h("3")},
	})
	new := Build(map[string][]Hash{
		"a": {h("99")}, // changed
		"b": {h("88")}, // changed
		"c": {h("3")},  // unchanged
	})

	r := DiffWithOptions(old, new, &DiffOptions{Filter: []string{"a"}})
	if len(r.Changed) != 1 || r.Changed[0] != "a" {
		t.Errorf("filter should limit to 'a', got %v", r.Changed)
	}
}

func TestDiffWithOptions_MaxChanges(t *testing.T) {
	old := Build(map[string][]Hash{
		"a": {h("1")},
		"b": {h("2")},
		"c": {h("3")},
	})
	new := Build(map[string][]Hash{
		"a": {h("99")},
		"b": {h("88")},
		"c": {h("77")},
	})

	r := DiffWithOptions(old, new, &DiffOptions{MaxChanges: 2})
	total := len(r.Added) + len(r.Removed) + len(r.Changed)
	if total > 2 {
		t.Errorf("MaxChanges=2 but got %d changes", total)
	}
	if !r.Truncated {
		t.Error("expected Truncated=true")
	}
}

func TestDiffLeaves(t *testing.T) {
	old := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c")},
	})
	new := Build(map[string][]Hash{
		"pkg": {h("b"), h("c"), h("d")},
	})

	added, removed := DiffLeaves(old, new, "pkg")
	if len(added) != 1 {
		t.Errorf("expected 1 added leaf, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 removed leaf, got %d", len(removed))
	}
	if added[0] != h("d") {
		t.Errorf("expected 'd' added")
	}
	if removed[0] != h("a") {
		t.Errorf("expected 'a' removed")
	}
}

func TestDiffLeaves_MissingGroup(t *testing.T) {
	f := Build(map[string][]Hash{"a": {h("1")}})
	added, removed := DiffLeaves(f, f, "nonexistent")
	if len(added) != 0 || len(removed) != 0 {
		t.Error("missing group should have empty diff")
	}
}
