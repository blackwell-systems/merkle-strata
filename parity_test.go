package merklestrata

import (
	"crypto/sha256"
	"testing"
)

// This test verifies hash parity with knowing's internal/snapshot implementation.
// It replicates knowing's hash construction exactly:
//   - ComputeMerkleNodeHash: SHA-256("merkle\x00" || left || right)
//   - BuildMerkleTree: sort leaves, recursive binary combine, odd = self-pair
//   - BuildHierarchicalTree: group by "pkg:edgeType", build subtrees, build pkg trees, build repo tree
//
// If this test passes, merkle-forest with WithPrefix([]byte("merkle\x00")) produces
// identical roots to knowing's internal/snapshot/hierarchical.go.

var knowingPrefix = []byte("merkle\x00")

// knowingCombine replicates types.ComputeMerkleNodeHash exactly.
func knowingCombine(left, right Hash) Hash {
	h := sha256.New()
	h.Write(knowingPrefix)
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// knowingBuildRoot replicates snapshot.computeMerkleRoot exactly.
func knowingBuildRoot(hashes []Hash) Hash {
	if len(hashes) == 0 {
		return Hash{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}
	var next []Hash
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			next = append(next, knowingCombine(hashes[i], hashes[i+1]))
		} else {
			next = append(next, knowingCombine(hashes[i], hashes[i]))
		}
	}
	return knowingBuildRoot(next)
}

func TestParity_CombineHash(t *testing.T) {
	a := h("left")
	b := h("right")

	// merkle-forest with knowing prefix.
	got := combineWithPrefix(a, b, knowingPrefix)

	// Knowing's implementation.
	want := knowingCombine(a, b)

	if got != want {
		t.Fatalf("combine mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestParity_FlatTreeRoot(t *testing.T) {
	leaves := []Hash{h("e1"), h("e2"), h("e3"), h("e4"), h("e5")}

	// Sort (same as knowing's BuildMerkleTree).
	sorted := make([]Hash, len(leaves))
	copy(sorted, leaves)
	SortHashes(sorted)

	// merkle-forest.
	got := computeRootWithPrefix(sorted, knowingPrefix)

	// Knowing's BuildMerkleTree (replicated).
	want := knowingBuildRoot(sorted)

	if got != want {
		t.Fatalf("flat tree root mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestParity_HierarchicalTree(t *testing.T) {
	// Replicate knowing's BuildHierarchicalTree logic:
	// 1. Group edges by "pkg:edgeType"
	// 2. Build merkle tree per group -> edgeTypeRoots
	// 3. Group edgeTypeRoots by pkg -> build merkle tree per pkg -> packageRoots
	// 4. Sort packageRoots by hash bytes -> build merkle tree -> repo root

	inputs := []MultiLevelInput{
		{Leaf: h("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e2"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: h("e3"), Group: "pkg/auth", Subgroup: "imports"},
		{Leaf: h("e4"), Group: "pkg/store", Subgroup: "calls"},
		{Leaf: h("e5"), Group: "pkg/store", Subgroup: "references"},
	}

	// --- Knowing's algorithm (manual) ---

	// Step 1: group by "pkg:edgeType", sort leaves, compute edgeType roots.
	authCalls := []Hash{h("e1"), h("e2")}
	SortHashes(authCalls)
	authCallsRoot := knowingBuildRoot(authCalls)

	authImports := []Hash{h("e3")}
	SortHashes(authImports)
	authImportsRoot := knowingBuildRoot(authImports)

	storeCalls := []Hash{h("e4")}
	SortHashes(storeCalls)
	storeCallsRoot := knowingBuildRoot(storeCalls)

	storeRefs := []Hash{h("e5")}
	SortHashes(storeRefs)
	storeRefsRoot := knowingBuildRoot(storeRefs)

	// Step 2: group edgeType roots by package, sort, compute package roots.
	authETRoots := []Hash{authCallsRoot, authImportsRoot}
	SortHashes(authETRoots)
	authPkgRoot := knowingBuildRoot(authETRoots)

	storeETRoots := []Hash{storeCallsRoot, storeRefsRoot}
	SortHashes(storeETRoots)
	storePkgRoot := knowingBuildRoot(storeETRoots)

	// Step 3: sort package roots BY HASH (not by name), compute repo root.
	// NOTE: knowing sorts package root hashes by bytes.Compare, NOT by package name.
	pkgRoots := []Hash{authPkgRoot, storePkgRoot}
	SortHashes(pkgRoots)
	wantRoot := knowingBuildRoot(pkgRoots)

	// --- merkle-forest ---
	ml := BuildMultiLevel(inputs, WithPrefix(knowingPrefix))

	if ml.Root != wantRoot {
		t.Fatalf("root mismatch:\n  merkle-forest: %x\n  knowing:       %x", ml.Root, wantRoot)
	}

	// Also verify group roots match.
	if ml.GroupRoots["pkg/auth"] != authPkgRoot {
		t.Errorf("pkg/auth root mismatch:\n  got:  %x\n  want: %x", ml.GroupRoots["pkg/auth"], authPkgRoot)
	}
	if ml.GroupRoots["pkg/store"] != storePkgRoot {
		t.Errorf("pkg/store root mismatch:\n  got:  %x\n  want: %x", ml.GroupRoots["pkg/store"], storePkgRoot)
	}

	// Verify subgroup roots match.
	if ml.SubgroupRoots["pkg/auth:calls"] != authCallsRoot {
		t.Errorf("pkg/auth:calls root mismatch")
	}
	if ml.SubgroupRoots["pkg/auth:imports"] != authImportsRoot {
		t.Errorf("pkg/auth:imports root mismatch")
	}
	if ml.SubgroupRoots["pkg/store:calls"] != storeCallsRoot {
		t.Errorf("pkg/store:calls root mismatch")
	}
	if ml.SubgroupRoots["pkg/store:references"] != storeRefsRoot {
		t.Errorf("pkg/store:references root mismatch")
	}

	// Verify SubgraphRoot matches knowing's SubgraphRoot.
	// knowing: sort package names -> collect their roots in name order -> BuildMerkleTree
	// Wait, knowing's SubgraphRoot sorts names then collects roots in that order,
	// but BuildMerkleTree re-sorts by hash. So effectively it's: collect roots, sort by hash, merkle.
	subRoot := ml.SubgraphRoot([]string{"pkg/auth"})
	// Single package SubgraphRoot = just the package root itself (single leaf tree = leaf).
	if subRoot != authPkgRoot {
		t.Errorf("SubgraphRoot(pkg/auth) mismatch:\n  got:  %x\n  want: %x", subRoot, authPkgRoot)
	}

	t.Logf("PARITY VERIFIED: merkle-forest with WithPrefix(\"merkle\\x00\") produces identical hashes to knowing")
}
