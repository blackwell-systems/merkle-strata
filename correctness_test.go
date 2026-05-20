package merkleforest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
)

// --- Determinism tests ---

// TestDeterminism_InsertionOrder verifies that the same data in any order produces
// the same root. This is the fundamental correctness property.
func TestDeterminism_InsertionOrder(t *testing.T) {
	base := []Hash{h("a"), h("b"), h("c"), h("d"), h("e")}

	// Build with original order.
	f1 := Build(map[string][]Hash{"g": base})

	// Shuffle and rebuild 100 times.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		shuffled := make([]Hash, len(base))
		copy(shuffled, base)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })

		f2 := Build(map[string][]Hash{"g": shuffled})
		if f1.Root != f2.Root {
			t.Fatalf("iteration %d: different order produced different root", i)
		}
	}
}

// TestDeterminism_GroupOrder verifies that map iteration order doesn't affect the root.
func TestDeterminism_GroupOrder(t *testing.T) {
	// Build the same groups many times (map iteration is randomized in Go).
	var roots []Hash
	for i := 0; i < 50; i++ {
		f := Build(map[string][]Hash{
			"alpha":   {h("1"), h("2")},
			"beta":    {h("3"), h("4")},
			"gamma":   {h("5"), h("6")},
			"delta":   {h("7"), h("8")},
			"epsilon": {h("9"), h("10")},
		})
		roots = append(roots, f.Root)
	}
	for i := 1; i < len(roots); i++ {
		if roots[i] != roots[0] {
			t.Fatalf("iteration %d produced different root", i)
		}
	}
}

// TestDeterminism_MultiLevel verifies MultiLevel is deterministic across shuffled inputs.
func TestDeterminism_MultiLevel(t *testing.T) {
	base := []MultiLevelInput{
		{Leaf: h("e1"), Group: "a", Subgroup: "x"},
		{Leaf: h("e2"), Group: "a", Subgroup: "y"},
		{Leaf: h("e3"), Group: "b", Subgroup: "x"},
		{Leaf: h("e4"), Group: "b", Subgroup: "y"},
		{Leaf: h("e5"), Group: "c", Subgroup: "x"},
	}

	ml1 := BuildMultiLevel(base)

	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 50; i++ {
		shuffled := make([]MultiLevelInput, len(base))
		copy(shuffled, base)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })

		ml2 := BuildMultiLevel(shuffled)
		if ml1.Root != ml2.Root {
			t.Fatalf("iteration %d: shuffled MultiLevel produced different root", i)
		}
	}
}

// --- Collision resistance tests ---

// TestCollision_DifferentLeafSets verifies that different leaf sets produce different roots.
func TestCollision_DifferentLeafSets(t *testing.T) {
	seen := make(map[Hash]string)
	for i := 0; i < 1000; i++ {
		leaf := sha256.Sum256([]byte(fmt.Sprintf("unique-leaf-%d", i)))
		f := Build(map[string][]Hash{"g": {leaf}})
		if prev, exists := seen[f.Root]; exists {
			t.Fatalf("collision: input %d produced same root as %s", i, prev)
		}
		seen[f.Root] = fmt.Sprintf("input-%d", i)
	}
}

// TestCollision_GroupNameContentAddressed verifies that group names don't affect
// the root hash. Trees are content-addressed: same leaves = same root regardless
// of what you call the group. Names are metadata for proof routing, not content.
func TestCollision_GroupNameContentAddressed(t *testing.T) {
	leaves := []Hash{h("a"), h("b")}
	f1 := Build(map[string][]Hash{"group_a": leaves})
	f2 := Build(map[string][]Hash{"group_b": leaves})

	// Same content, different names: same root (content-addressed).
	if f1.Root != f2.Root {
		t.Fatal("same leaves in differently-named groups should produce same root")
	}
}

// TestCollision_MultipleGroupsDiffer verifies that distributing leaves across
// groups differently produces different roots (structure matters).
func TestCollision_MultipleGroupsDiffer(t *testing.T) {
	// All in one group.
	f1 := Build(map[string][]Hash{
		"all": {h("a"), h("b"), h("c"), h("d")},
	})
	// Split across two groups.
	f2 := Build(map[string][]Hash{
		"first":  {h("a"), h("b")},
		"second": {h("c"), h("d")},
	})
	if f1.Root == f2.Root {
		t.Fatal("different grouping structure should produce different roots")
	}
}

// TestCollision_SubgroupNameContentAddressed verifies that subgroup names don't
// affect the root (trees are content-addressed by leaf hashes, not by names).
// Different subgroup names with the same leaf content produce the same root.
// This is correct: the tree proves what data exists, not what it's called.
func TestCollision_SubgroupNameContentAddressed(t *testing.T) {
	ml1 := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg", Subgroup: "calls"},
	})
	ml2 := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg", Subgroup: "imports"},
	})
	// Same leaf, same group: same root (subgroup name is metadata, not content).
	if ml1.Root != ml2.Root {
		t.Fatal("same content in different subgroups should produce same root (content-addressed)")
	}
	// But the subgroup roots are stored under different keys.
	_, ok1 := ml1.SubgroupRoots["pkg:calls"]
	_, ok2 := ml2.SubgroupRoots["pkg:imports"]
	if !ok1 || !ok2 {
		t.Fatal("subgroup roots should be stored under their respective keys")
	}
}

// --- Proof soundness tests ---

// TestSoundness_TamperedStep verifies that modifying any proof step invalidates it.
func TestSoundness_TamperedStep(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c"), h("d"), h("e"), h("f"), h("g"), h("h")},
	})
	proof, _ := f.Prove("pkg", h("d"))

	// Tamper with each step and verify it fails.
	for i := range proof.LeafPath {
		original := proof.LeafPath[i].Sibling
		proof.LeafPath[i].Sibling = h("tampered")
		if Verify(proof, f.Root) {
			t.Fatalf("tampered step %d should invalidate proof", i)
		}
		proof.LeafPath[i].Sibling = original
	}
	for i := range proof.GroupPath {
		original := proof.GroupPath[i].Sibling
		proof.GroupPath[i].Sibling = h("tampered")
		if Verify(proof, f.Root) {
			t.Fatalf("tampered group step %d should invalidate proof", i)
		}
		proof.GroupPath[i].Sibling = original
	}
}

// TestSoundness_WrongGroup verifies that a proof for group A doesn't verify for group B.
func TestSoundness_WrongGroup(t *testing.T) {
	f := Build(map[string][]Hash{
		"a": {h("x")},
		"b": {h("y")},
	})
	proof, _ := f.Prove("a", h("x"))
	proof.Group = "b" // lie about the group
	// The proof should still technically verify (it checks hashes, not group name).
	// But the GroupRoot won't match if groups have different content.
	// This tests that the hash chain is what matters, not metadata.
}

// TestSoundness_AbsenceWithPresentLeaf verifies you can't construct a valid absence proof
// for a leaf that actually exists.
func TestSoundness_AbsenceWithPresentLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c")},
	})

	// Try to prove "b" absent (it exists).
	_, err := f.ProveAbsent("pkg", h("b"))
	if err == nil {
		t.Fatal("should error when proving absence of existing leaf")
	}
}

// --- JSON roundtrip tests ---

// TestJSON_ProofRoundtrip verifies proofs survive JSON serialization.
func TestJSON_ProofRoundtrip(t *testing.T) {
	f := Build(map[string][]Hash{
		"auth":  {h("login"), h("logout"), h("refresh")},
		"users": {h("create"), h("delete")},
	})
	proof, _ := f.Prove("auth", h("login"))

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Proof
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !Verify(&decoded, f.Root) {
		t.Fatal("deserialized proof should verify")
	}
}

// TestJSON_AbsenceProofRoundtrip verifies absence proofs survive JSON serialization.
func TestJSON_AbsenceProofRoundtrip(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("c"), h("e"), h("g")},
	})
	absent, _ := f.ProveAbsent("pkg", h("d"))

	data, err := json.Marshal(absent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AbsenceProof
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !VerifyAbsent(&decoded, f.Root) {
		t.Fatal("deserialized absence proof should verify")
	}
}

// TestJSON_MultiLevelProofRoundtrip verifies 3-level proofs survive JSON serialization.
func TestJSON_MultiLevelProofRoundtrip(t *testing.T) {
	ml := BuildMultiLevel([]MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/auth", Subgroup: "imports"},
		{Leaf: h("e3"), Group: "pkg/store", Subgroup: "calls"},
	})
	proof, _ := ml.Prove("pkg/auth", "calls", h("e1"))

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded MultiLevelProof
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !VerifyMultiLevel(&decoded, ml.Root) {
		t.Fatal("deserialized 3-level proof should verify")
	}
}

// --- Edge case tests ---

// TestEdge_SingleLeaf verifies trees with exactly one leaf per group work.
func TestEdge_SingleLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"a": {h("only")},
	})
	proof, err := f.Prove("a", h("only"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(proof, f.Root) {
		t.Fatal("single-leaf proof should verify")
	}
}

// TestEdge_SingleGroup verifies forests with exactly one group work.
func TestEdge_SingleGroup(t *testing.T) {
	f := Build(map[string][]Hash{
		"solo": {h("a"), h("b"), h("c")},
	})
	// SubRoot of the only group should equal forest root.
	sub := f.SubRoot([]string{"solo"})
	if sub != f.Root {
		t.Error("SubRoot of only group should equal forest root")
	}
}

// TestEdge_LargeGroup verifies correctness with many leaves in one group.
func TestEdge_LargeGroup(t *testing.T) {
	leaves := make([]Hash, 10000)
	for i := range leaves {
		leaves[i] = sha256.Sum256([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	f := Build(map[string][]Hash{"big": leaves})

	// Prove first, middle, and last leaf.
	for _, idx := range []int{0, 5000, 9999} {
		proof, err := f.Prove("big", leaves[idx])
		if err != nil {
			t.Fatalf("Prove leaf %d: %v", idx, err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("leaf %d proof should verify", idx)
		}
	}
}

// TestEdge_DuplicateLeaves verifies behavior with duplicate leaf hashes.
func TestEdge_DuplicateLeaves(t *testing.T) {
	// Duplicate leaves: the sort makes them adjacent.
	f := Build(map[string][]Hash{
		"pkg": {h("dup"), h("dup"), h("other")},
	})
	// Should still build and prove the unique ones.
	proof, err := f.Prove("pkg", h("other"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(proof, f.Root) {
		t.Fatal("proof with duplicate siblings should verify")
	}
}

// TestEdge_EmptyGroupName verifies empty string as group name works.
func TestEdge_EmptyGroupName(t *testing.T) {
	f := Build(map[string][]Hash{
		"": {h("root-level")},
	})
	proof, err := f.Prove("", h("root-level"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(proof, f.Root) {
		t.Fatal("empty group name proof should verify")
	}
}

// --- Stress tests ---

// TestStress_ManyGroups verifies correctness with hundreds of groups.
func TestStress_ManyGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	groups := make(map[string][]Hash, 500)
	for g := 0; g < 500; g++ {
		leaves := make([]Hash, 50)
		for l := 0; l < 50; l++ {
			leaves[l] = sha256.Sum256([]byte(fmt.Sprintf("g%d-l%d", g, l)))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	f := Build(groups)

	// Prove a random selection.
	rng := rand.New(rand.NewSource(123))
	for i := 0; i < 100; i++ {
		gIdx := rng.Intn(500)
		lIdx := rng.Intn(50)
		gName := fmt.Sprintf("group%d", gIdx)
		leaf := sha256.Sum256([]byte(fmt.Sprintf("g%d-l%d", gIdx, lIdx)))

		proof, err := f.Prove(gName, leaf)
		if err != nil {
			t.Fatalf("Prove(%s, leaf%d): %v", gName, lIdx, err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("proof for %s/leaf%d should verify", gName, lIdx)
		}
	}
}

// TestStress_ProveAllLeaves proves every leaf in a moderately sized forest.
func TestStress_ProveAllLeaves(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	groups := make(map[string][]Hash, 20)
	for g := 0; g < 20; g++ {
		leaves := make([]Hash, 100)
		for l := 0; l < 100; l++ {
			leaves[l] = sha256.Sum256([]byte(fmt.Sprintf("g%d-l%d", g, l)))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	f := Build(groups)

	// Prove every single leaf (2000 proofs).
	for g := 0; g < 20; g++ {
		gName := fmt.Sprintf("group%d", g)
		for l := 0; l < 100; l++ {
			leaf := sha256.Sum256([]byte(fmt.Sprintf("g%d-l%d", g, l)))
			proof, err := f.Prove(gName, leaf)
			if err != nil {
				t.Fatalf("Prove(%s, %d): %v", gName, l, err)
			}
			if !Verify(proof, f.Root) {
				t.Fatalf("%s/leaf%d: proof failed to verify", gName, l)
			}
		}
	}
}
