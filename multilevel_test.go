package merklestrata

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

func TestMultiLevel_ProveAbsent(t *testing.T) {
	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e3"), Group: "pkg/auth", Subgroup: "imports"},
	}
	ml := BuildMultiLevel(inputs)

	// Prove a missing leaf is absent.
	absent, err := ml.ProveAbsent("pkg/auth", "calls", h("missing"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyMultiLevelAbsent(absent, ml.Root) {
		t.Fatal("absence proof should verify")
	}
}

func TestMultiLevel_ProveAbsent_SubgroupMissing(t *testing.T) {
	ml := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg", Subgroup: "calls"},
	})

	absent, err := ml.ProveAbsent("pkg", "nonexistent", h("anything"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyMultiLevelAbsent(absent, ml.Root) {
		t.Fatal("absence proof for missing subgroup should verify")
	}
}

func TestMultiLevel_ProveAbsent_LeafExists(t *testing.T) {
	ml := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg", Subgroup: "calls"},
	})

	_, err := ml.ProveAbsent("pkg", "calls", h("e1"))
	if err == nil {
		t.Fatal("expected error when proving absence of existing leaf")
	}
}

// TestMultiLevel_VerifyAbsent_ForgedNonAdjacentNeighbors is the multi-level
// analogue of the two-level forgery test. The subgroup "calls" holds leaves
// {a,b,c,d,e}, whose sorted hash order is d(0), c(1), b(2), e(3), a(4). "b" is
// genuinely present at index 2. A malicious prover brackets it with the
// NON-adjacent leaves d(0) and e(3): both included, both satisfying
// d < b < e in sort order, yet "b" (and "c") sit between them. The adjacency
// check must reject this forged absence proof for a present leaf.
func TestMultiLevel_VerifyAbsent_ForgedNonAdjacentNeighbors(t *testing.T) {
	ml := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("a"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("b"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("c"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("d"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("e"), Group: "pkg", Subgroup: "calls"},
	})

	left, err := ml.Prove("pkg", "calls", h("d")) // index 0
	if err != nil {
		t.Fatalf("Prove(d): %v", err)
	}
	right, err := ml.Prove("pkg", "calls", h("e")) // index 3
	if err != nil {
		t.Fatalf("Prove(e): %v", err)
	}

	// Sanity: valid inclusion proofs that are non-adjacent.
	if !VerifyMultiLevel(left, ml.Root) || !VerifyMultiLevel(right, ml.Root) {
		t.Fatal("neighbor inclusion proofs should verify on their own")
	}
	if left.LeafIndex+1 == right.LeafIndex {
		t.Fatalf("test setup is wrong: neighbors are adjacent (%d, %d)", left.LeafIndex, right.LeafIndex)
	}

	dHash := h("d")
	eHash := h("e")
	forged := &MultiLevelAbsenceProof{
		Missing:    h("b"), // actually present at index 2
		Group:      "pkg",
		Subgroup:   "calls",
		Left:       &dHash,
		Right:      &eHash,
		LeftProof:  left,
		RightProof: right,
		Root:       ml.Root,
	}

	if VerifyMultiLevelAbsent(forged, ml.Root) {
		t.Fatal("absence proof with non-adjacent neighbors bracketing a present leaf must be rejected")
	}
}

// TestMultiLevel_VerifyAbsent_BoundaryNeighbors confirms legitimate multi-level
// absence proofs still verify across both boundaries and the interior. Sorted
// hash order of {a,b,c,d,e} is d, c, b, e, a, so "zzz" sorts before the first
// leaf, "k0" after the last, and "q" in the interior.
func TestMultiLevel_VerifyAbsent_BoundaryNeighbors(t *testing.T) {
	ml := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("a"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("b"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("c"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("d"), Group: "pkg", Subgroup: "calls"},
		{Leaf: h("e"), Group: "pkg", Subgroup: "calls"},
	})

	before, err := ml.ProveAbsent("pkg", "calls", h("zzz"))
	if err != nil {
		t.Fatalf("ProveAbsent(before): %v", err)
	}
	if before.LeftProof != nil || before.RightProof == nil {
		t.Fatal("leaf before all should have only a right neighbor")
	}
	if before.RightProof.LeafIndex != 0 {
		t.Fatalf("right neighbor should be first leaf, got index %d", before.RightProof.LeafIndex)
	}
	if !VerifyMultiLevelAbsent(before, ml.Root) {
		t.Fatal("before-all absence proof should verify")
	}

	after, err := ml.ProveAbsent("pkg", "calls", h("k0"))
	if err != nil {
		t.Fatalf("ProveAbsent(after): %v", err)
	}
	if after.RightProof != nil || after.LeftProof == nil {
		t.Fatal("leaf after all should have only a left neighbor")
	}
	if after.LeftProof.LeafIndex != after.LeftProof.LeafCount-1 {
		t.Fatalf("left neighbor should be last leaf, got index %d of %d", after.LeftProof.LeafIndex, after.LeftProof.LeafCount)
	}
	if !VerifyMultiLevelAbsent(after, ml.Root) {
		t.Fatal("after-all absence proof should verify")
	}

	interior, err := ml.ProveAbsent("pkg", "calls", h("q"))
	if err != nil {
		t.Fatalf("ProveAbsent(interior): %v", err)
	}
	if interior.LeftProof == nil || interior.RightProof == nil {
		t.Fatal("interior absence should have both neighbors")
	}
	if interior.LeftProof.LeafIndex+1 != interior.RightProof.LeafIndex {
		t.Fatal("interior neighbors should be adjacent")
	}
	if !VerifyMultiLevelAbsent(interior, ml.Root) {
		t.Fatal("interior absence proof should verify")
	}
}
