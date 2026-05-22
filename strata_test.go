package merklestrata

import (
	"crypto/sha256"
	"testing"
)

func h(s string) Hash {
	return sha256.Sum256([]byte(s))
}

func TestBuild_Empty(t *testing.T) {
	f := Build(nil)
	if f.Root != (Hash{}) {
		t.Errorf("empty forest should have zero root")
	}
}

func TestBuild_SingleGroup(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c")},
	})
	if f.Root == (Hash{}) {
		t.Fatal("root should not be zero")
	}
	root, ok := f.GroupRoot("pkg")
	if !ok {
		t.Fatal("group 'pkg' should exist")
	}
	if root == (Hash{}) {
		t.Fatal("group root should not be zero")
	}
}

func TestBuild_Deterministic(t *testing.T) {
	// Same data in different order produces same root.
	f1 := Build(map[string][]Hash{
		"a": {h("x"), h("y"), h("z")},
		"b": {h("1"), h("2")},
	})
	f2 := Build(map[string][]Hash{
		"b": {h("2"), h("1")},
		"a": {h("z"), h("x"), h("y")},
	})
	if f1.Root != f2.Root {
		t.Errorf("same data different order should produce same root")
	}
}

func TestBuild_DifferentData(t *testing.T) {
	f1 := Build(map[string][]Hash{
		"a": {h("x"), h("y")},
	})
	f2 := Build(map[string][]Hash{
		"a": {h("x"), h("z")},
	})
	if f1.Root == f2.Root {
		t.Errorf("different data should produce different roots")
	}
}

func TestGroups(t *testing.T) {
	f := Build(map[string][]Hash{
		"c": {h("1")},
		"a": {h("2")},
		"b": {h("3")},
	})
	groups := f.Groups()
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if groups[0] != "a" || groups[1] != "b" || groups[2] != "c" {
		t.Errorf("groups should be sorted: got %v", groups)
	}
}

func TestSubRoot(t *testing.T) {
	f := Build(map[string][]Hash{
		"a": {h("1"), h("2")},
		"b": {h("3"), h("4")},
		"c": {h("5"), h("6")},
	})

	// SubRoot of all groups should NOT equal forest root (different construction).
	// SubRoot uses only selected group roots; forest root uses all.
	sub := f.SubRoot([]string{"a", "b"})
	if sub == (Hash{}) {
		t.Fatal("SubRoot should not be zero")
	}
	if sub == f.Root {
		t.Error("SubRoot of subset should differ from full root")
	}

	// SubRoot is deterministic regardless of input order.
	sub2 := f.SubRoot([]string{"b", "a"})
	if sub != sub2 {
		t.Error("SubRoot should be order-independent")
	}

	// SubRoot of non-existent groups is zero.
	empty := f.SubRoot([]string{"nonexistent"})
	if empty != (Hash{}) {
		t.Error("SubRoot of missing groups should be zero")
	}
}

func TestSubRoot_AllGroups(t *testing.T) {
	f := Build(map[string][]Hash{
		"a": {h("1")},
		"b": {h("2")},
	})

	// SubRoot of all groups should equal the forest root.
	sub := f.SubRoot([]string{"a", "b"})
	if sub != f.Root {
		t.Error("SubRoot of all groups should equal forest root")
	}
}
