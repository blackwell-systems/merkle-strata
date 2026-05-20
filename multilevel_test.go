package merkleforest

import (
	"testing"
)

func TestMultiLevel_Build(t *testing.T) {
	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e3"), Group: "pkg/auth", Subgroup: "imports"},
		{Leaf: h("e4"), Group: "pkg/store", Subgroup: "calls"},
	}

	ml := BuildMultiLevel(inputs)
	if ml.Root == (Hash{}) {
		t.Fatal("root should not be zero")
	}
	if len(ml.GroupRoots) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(ml.GroupRoots))
	}
	if len(ml.SubgroupRoots) != 3 {
		t.Fatalf("expected 3 subgroups, got %d", len(ml.SubgroupRoots))
	}
	if ml.TotalLeaves != 4 {
		t.Fatalf("expected 4 total leaves, got %d", ml.TotalLeaves)
	}
	if ml.GroupLeafCounts["pkg/auth"] != 3 {
		t.Errorf("pkg/auth should have 3 leaves, got %d", ml.GroupLeafCounts["pkg/auth"])
	}
}

func TestMultiLevel_Deterministic(t *testing.T) {
	inputs1 := []MultiLevelInput{
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e2"), Group: "a", Subgroup: "y"},
		{Leaf: h("e3"), Group: "b", Subgroup: "x"},
	}
	inputs2 := []MultiLevelInput{
		{Leaf: h("e3"), Group: "b", Subgroup: "x"},
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e2"), Group: "a", Subgroup: "y"},
	}

	ml1 := BuildMultiLevel(inputs1)
	ml2 := BuildMultiLevel(inputs2)
	if ml1.Root != ml2.Root {
		t.Error("same inputs in different order should produce same root")
	}
}

func TestMultiLevel_Prove(t *testing.T) {
	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e3"), Group: "pkg/auth", Subgroup: "imports"},
		{Leaf: h("e4"), Group: "pkg/store", Subgroup: "calls"},
		{Leaf: h("e5"), Group: "pkg/store", Subgroup: "calls"},
	}

	ml := BuildMultiLevel(inputs)

	// Prove each leaf.
	for _, inp := range inputs {
		proof, err := ml.Prove(inp.Group, inp.Subgroup, inp.Leaf)
		if err != nil {
			t.Fatalf("Prove(%s, %s, %x): %v", inp.Group, inp.Subgroup, inp.Leaf[:4], err)
		}
		if !VerifyMultiLevel(proof, ml.Root) {
			t.Fatalf("proof for %x should verify", inp.Leaf[:4])
		}
	}
}

func TestMultiLevel_ProveWithPrefix(t *testing.T) {
	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg", Subgroup: "calls"},
	}

	// Build with knowing's prefix.
	knowingPrefix := []byte("merkle\x00")
	ml := BuildMultiLevel(inputs, WithPrefix(knowingPrefix))

	proof, err := ml.Prove("pkg", "calls", h("e1"))
	if err != nil {
		t.Fatal(err)
	}

	// Should verify with same prefix.
	if !VerifyMultiLevelWithPrefix(proof, ml.Root, knowingPrefix) {
		t.Fatal("proof should verify with matching prefix")
	}

	// Should NOT verify with default prefix.
	if VerifyMultiLevel(proof, ml.Root) {
		t.Fatal("proof should NOT verify with wrong prefix")
	}
}

func TestMultiLevel_SubgraphRoot(t *testing.T) {
	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e2"), Group: "b", Subgroup: "x"},
		{Leaf: h("e3"), Group: "c", Subgroup: "x"},
	}

	ml := BuildMultiLevel(inputs)

	sub := ml.SubgraphRoot([]string{"a", "b"})
	if sub == (Hash{}) {
		t.Fatal("SubgraphRoot should not be zero")
	}
	if sub == ml.Root {
		t.Error("SubgraphRoot of subset should differ from full root")
	}

	// Order independent.
	sub2 := ml.SubgraphRoot([]string{"b", "a"})
	if sub != sub2 {
		t.Error("SubgraphRoot should be order-independent")
	}

	// All groups = full root.
	all := ml.SubgraphRoot([]string{"a", "b", "c"})
	if all != ml.Root {
		t.Error("SubgraphRoot of all groups should equal root")
	}
}

func TestMultiLevel_DiffChanged(t *testing.T) {
	old := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/store", Subgroup: "calls"},
	})
	new := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e99"), Group: "pkg/store", Subgroup: "calls"}, // changed
	})

	diff := DiffMultiLevelTrees(old, new)
	if !diff.RootChanged {
		t.Fatal("root should have changed")
	}
	if len(diff.ChangedGroups) != 1 || diff.ChangedGroups[0] != "pkg/store" {
		t.Errorf("expected pkg/store changed, got %v", diff.ChangedGroups)
	}
	if len(diff.ChangedSubgroups) != 1 || diff.ChangedSubgroups[0] != "pkg/store:calls" {
		t.Errorf("expected pkg/store:calls changed, got %v", diff.ChangedSubgroups)
	}
}

func TestMultiLevel_DiffAddedRemoved(t *testing.T) {
	old := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e2"), Group: "b", Subgroup: "x"},
	})
	new := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e3"), Group: "c", Subgroup: "x"},
	})

	diff := DiffMultiLevelTrees(old, new)
	if len(diff.AddedGroups) != 1 || diff.AddedGroups[0] != "c" {
		t.Errorf("expected 'c' added, got %v", diff.AddedGroups)
	}
	if len(diff.RemovedGroups) != 1 || diff.RemovedGroups[0] != "b" {
		t.Errorf("expected 'b' removed, got %v", diff.RemovedGroups)
	}
}

func TestMultiLevel_Empty(t *testing.T) {
	ml := BuildMultiLevel(nil)
	if ml.Root != (Hash{}) {
		t.Error("empty multilevel should have zero root")
	}
	if ml.TotalLeaves != 0 {
		t.Error("empty should have 0 leaves")
	}
}
