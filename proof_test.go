package merklestrata

import (
	"testing"
)

func TestProve_SingleLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("leaf1")},
	})

	proof, err := f.Prove("pkg", h("leaf1"))
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if !Verify(proof, f.Root) {
		t.Fatal("proof should verify")
	}
}

func TestProve_MultipleLeaves(t *testing.T) {
	f := Build(map[string][]Hash{
		"auth":  {h("login"), h("logout"), h("refresh")},
		"users": {h("create"), h("delete"), h("update")},
	})

	for _, leaf := range []Hash{h("login"), h("logout"), h("refresh")} {
		proof, err := f.Prove("auth", leaf)
		if err != nil {
			t.Fatalf("Prove(auth, %x): %v", leaf[:4], err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("proof for %x should verify", leaf[:4])
		}
	}

	for _, leaf := range []Hash{h("create"), h("delete"), h("update")} {
		proof, err := f.Prove("users", leaf)
		if err != nil {
			t.Fatalf("Prove(users, %x): %v", leaf[:4], err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("proof for %x should verify", leaf[:4])
		}
	}
}

func TestProve_GroupNotFound(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a")},
	})
	_, err := f.Prove("nonexistent", h("a"))
	if err == nil {
		t.Fatal("expected error for missing group")
	}
}

func TestProve_LeafNotFound(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})
	_, err := f.Prove("pkg", h("missing"))
	if err == nil {
		t.Fatal("expected error for missing leaf")
	}
}

func TestVerify_TamperedLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c")},
	})
	proof, _ := f.Prove("pkg", h("a"))
	proof.Leaf = h("tampered")
	if Verify(proof, f.Root) {
		t.Fatal("tampered proof should not verify")
	}
}

func TestVerify_WrongRoot(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})
	proof, _ := f.Prove("pkg", h("a"))
	if Verify(proof, h("wrong-root")) {
		t.Fatal("proof against wrong root should not verify")
	}
}

func TestVerify_Nil(t *testing.T) {
	if Verify(nil, Hash{}) {
		t.Fatal("nil proof should not verify")
	}
}

func TestProveAbsent_LeafMissing(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("c"), h("e")},
	})

	// "b" is between "a" and "c" (depends on hash ordering, but test the mechanism).
	absent, err := f.ProveAbsent("pkg", h("missing"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyAbsent(absent, f.Root) {
		t.Fatal("absence proof should verify")
	}
}

func TestProveAbsent_GroupMissing(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a")},
	})

	absent, err := f.ProveAbsent("nonexistent", h("anything"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyAbsent(absent, f.Root) {
		t.Fatal("absence proof for missing group should verify")
	}
}

func TestProveAbsent_LeafExists(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})

	_, err := f.ProveAbsent("pkg", h("a"))
	if err == nil {
		t.Fatal("expected error when proving absence of existing leaf")
	}
}

func TestVerifyAbsent_Nil(t *testing.T) {
	if VerifyAbsent(nil, Hash{}) {
		t.Fatal("nil absence proof should not verify")
	}
}

// TestVerifyAbsent_ForgedNonAdjacentNeighbors demonstrates the adjacency fix.
// The sorted hash order for these labels is d(0), c(1), b(2), e(3), a(4), so
// "b" is genuinely present at index 2, bracketed by c(1) and e(3). A malicious
// prover instead brackets "b" with the NON-adjacent leaves d(0) and e(3):
// both are included and satisfy d < b < e in sort order, yet they are not
// consecutive, so "b" (and "c") sit between them. Without the adjacency check
// this forged absence proof for a present leaf would verify. It must not.
func TestVerifyAbsent_ForgedNonAdjacentNeighbors(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c"), h("d"), h("e")},
	})

	left, err := f.Prove("pkg", h("d")) // index 0
	if err != nil {
		t.Fatalf("Prove(d): %v", err)
	}
	right, err := f.Prove("pkg", h("e")) // index 3
	if err != nil {
		t.Fatalf("Prove(e): %v", err)
	}

	// Sanity: the neighbors are valid inclusion proofs and non-adjacent.
	if !Verify(left, f.Root) || !Verify(right, f.Root) {
		t.Fatal("neighbor inclusion proofs should verify on their own")
	}
	if left.LeafIndex+1 == right.LeafIndex {
		t.Fatalf("test setup is wrong: neighbors are adjacent (%d, %d)", left.LeafIndex, right.LeafIndex)
	}

	dHash := h("d")
	eHash := h("e")
	forged := &AbsenceProof{
		Missing:    h("b"), // actually present at index 2
		Group:      "pkg",
		Left:       &dHash,
		Right:      &eHash,
		LeftProof:  left,
		RightProof: right,
		Root:       f.Root,
	}

	if VerifyAbsent(forged, f.Root) {
		t.Fatal("absence proof with non-adjacent neighbors bracketing a present leaf must be rejected")
	}
}

// TestVerifyAbsent_BoundaryNeighbors confirms the single-sided boundary cases
// still verify and carry the expected neighbor structure. Sorted hash order of
// {a,b,c,d,e} is d, c, b, e, a, so "zzz" sorts before the first leaf (right
// neighbor only, at index 0), "k0" sorts after the last leaf (left neighbor
// only, at the final index), and "q" lands in the interior (both neighbors).
func TestVerifyAbsent_BoundaryNeighbors(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c"), h("d"), h("e")},
	})

	// Before all leaves: only a right neighbor, which must be the first leaf.
	before, err := f.ProveAbsent("pkg", h("zzz"))
	if err != nil {
		t.Fatalf("ProveAbsent(before): %v", err)
	}
	if before.LeftProof != nil || before.RightProof == nil {
		t.Fatal("leaf before all should have only a right neighbor")
	}
	if before.RightProof.LeafIndex != 0 {
		t.Fatalf("right neighbor should be first leaf, got index %d", before.RightProof.LeafIndex)
	}
	if !VerifyAbsent(before, f.Root) {
		t.Fatal("before-all absence proof should verify")
	}

	// After all leaves: only a left neighbor, which must be the last leaf.
	after, err := f.ProveAbsent("pkg", h("k0"))
	if err != nil {
		t.Fatalf("ProveAbsent(after): %v", err)
	}
	if after.RightProof != nil || after.LeftProof == nil {
		t.Fatal("leaf after all should have only a left neighbor")
	}
	if after.LeftProof.LeafIndex != after.LeftProof.LeafCount-1 {
		t.Fatalf("left neighbor should be last leaf, got index %d of %d", after.LeftProof.LeafIndex, after.LeftProof.LeafCount)
	}
	if !VerifyAbsent(after, f.Root) {
		t.Fatal("after-all absence proof should verify")
	}

	// Interior: a genuinely missing leaf bracketed by two adjacent neighbors.
	interior, err := f.ProveAbsent("pkg", h("q"))
	if err != nil {
		t.Fatalf("ProveAbsent(interior): %v", err)
	}
	if interior.LeftProof == nil || interior.RightProof == nil {
		t.Fatal("interior absence should have both neighbors")
	}
	if interior.LeftProof.LeafIndex+1 != interior.RightProof.LeafIndex {
		t.Fatal("interior neighbors should be adjacent")
	}
	if !VerifyAbsent(interior, f.Root) {
		t.Fatal("interior absence proof should verify")
	}
}

func TestProve_ManyGroups(t *testing.T) {
	groups := map[string][]Hash{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		groups[name] = []Hash{h(name + "1"), h(name + "2"), h(name + "3")}
	}
	f := Build(groups)

	for name, leaves := range groups {
		for _, leaf := range leaves {
			proof, err := f.Prove(name, leaf)
			if err != nil {
				t.Fatalf("Prove(%s, %x): %v", name, leaf[:4], err)
			}
			if !Verify(proof, f.Root) {
				t.Fatalf("proof for %s/%x should verify", name, leaf[:4])
			}
		}
	}
}
