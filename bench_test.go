package merklestrata

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func benchHash(s string) Hash {
	return sha256.Sum256([]byte(s))
}

func buildBenchForest(numGroups, leavesPerGroup int) *Forest {
	groups := make(map[string][]Hash, numGroups)
	for g := 0; g < numGroups; g++ {
		leaves := make([]Hash, leavesPerGroup)
		for l := 0; l < leavesPerGroup; l++ {
			leaves[l] = benchHash(fmt.Sprintf("group%d-leaf%d", g, l))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	return Build(groups)
}

func buildBenchMultiLevel(numGroups, subgroupsPerGroup, leavesPerSubgroup int) *MultiLevel {
	var inputs []MultiLevelInput
	for g := 0; g < numGroups; g++ {
		for sg := 0; sg < subgroupsPerGroup; sg++ {
			for l := 0; l < leavesPerSubgroup; l++ {
				inputs = append(inputs, MultiLevelInput{
					Leaf:     benchHash(fmt.Sprintf("g%d-sg%d-l%d", g, sg, l)),
					Group:    fmt.Sprintf("group%d", g),
					Subgroup: fmt.Sprintf("subgroup%d", sg),
				})
			}
		}
	}
	return BuildMultiLevel(inputs)
}

// --- Build benchmarks ---

func BenchmarkBuild_10Groups_100Leaves(b *testing.B) {
	groups := make(map[string][]Hash, 10)
	for g := 0; g < 10; g++ {
		leaves := make([]Hash, 100)
		for l := 0; l < 100; l++ {
			leaves[l] = benchHash(fmt.Sprintf("g%d-l%d", g, l))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Build(groups)
	}
}

func BenchmarkBuild_100Groups_100Leaves(b *testing.B) {
	groups := make(map[string][]Hash, 100)
	for g := 0; g < 100; g++ {
		leaves := make([]Hash, 100)
		for l := 0; l < 100; l++ {
			leaves[l] = benchHash(fmt.Sprintf("g%d-l%d", g, l))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Build(groups)
	}
}

func BenchmarkBuild_100Groups_1000Leaves(b *testing.B) {
	groups := make(map[string][]Hash, 100)
	for g := 0; g < 100; g++ {
		leaves := make([]Hash, 1000)
		for l := 0; l < 1000; l++ {
			leaves[l] = benchHash(fmt.Sprintf("g%d-l%d", g, l))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Build(groups)
	}
}

func BenchmarkBuildMultiLevel_50Groups_5Subgroups_20Leaves(b *testing.B) {
	var inputs []MultiLevelInput
	for g := 0; g < 50; g++ {
		for sg := 0; sg < 5; sg++ {
			for l := 0; l < 20; l++ {
				inputs = append(inputs, MultiLevelInput{
					Leaf:     benchHash(fmt.Sprintf("g%d-sg%d-l%d", g, sg, l)),
					Group:    fmt.Sprintf("group%d", g),
					Subgroup: fmt.Sprintf("subgroup%d", sg),
				})
			}
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildMultiLevel(inputs)
	}
}

// --- Prove benchmarks ---

func BenchmarkProve_10Groups(b *testing.B) {
	f := buildBenchForest(10, 100)
	leaf := f.Leaves("group5")[50]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Prove("group5", leaf)
	}
}

func BenchmarkProve_100Groups(b *testing.B) {
	f := buildBenchForest(100, 100)
	leaf := f.Leaves("group50")[50]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Prove("group50", leaf)
	}
}

func BenchmarkProveMultiLevel(b *testing.B) {
	ml := buildBenchMultiLevel(50, 5, 20)
	leaf := benchHash("g25-sg2-l10")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ml.Prove("group25", "subgroup2", leaf)
	}
}

// --- Verify benchmarks ---

func BenchmarkVerify(b *testing.B) {
	f := buildBenchForest(100, 100)
	leaf := f.Leaves("group50")[50]
	proof, _ := f.Prove("group50", leaf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(proof, f.Root)
	}
}

func BenchmarkVerifyMultiLevel(b *testing.B) {
	ml := buildBenchMultiLevel(50, 5, 20)
	leaf := benchHash("g25-sg2-l10")
	proof, _ := ml.Prove("group25", "subgroup2", leaf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMultiLevel(proof, ml.Root)
	}
}

// --- Absence proof benchmarks ---

func BenchmarkProveAbsent(b *testing.B) {
	f := buildBenchForest(10, 100)
	missing := benchHash("nonexistent")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ProveAbsent("group5", missing)
	}
}

func BenchmarkVerifyAbsent(b *testing.B) {
	f := buildBenchForest(10, 100)
	missing := benchHash("nonexistent")
	proof, _ := f.ProveAbsent("group5", missing)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyAbsent(proof, f.Root)
	}
}

// --- Diff benchmarks ---

func BenchmarkDiff_100Groups_1Changed(b *testing.B) {
	old := buildBenchForest(100, 100)
	// Build new with one group changed.
	groups := make(map[string][]Hash, 100)
	for g := 0; g < 100; g++ {
		leaves := make([]Hash, 100)
		for l := 0; l < 100; l++ {
			if g == 50 && l == 0 {
				leaves[l] = benchHash("changed")
			} else {
				leaves[l] = benchHash(fmt.Sprintf("group%d-leaf%d", g, l))
			}
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	new := Build(groups)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Diff(old, new)
	}
}

func BenchmarkSubRoot_10of100(b *testing.B) {
	f := buildBenchForest(100, 100)
	subset := []string{"group10", "group20", "group30", "group40", "group50",
		"group60", "group70", "group80", "group90", "group99"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.SubRoot(subset)
	}
}

// --- Scale benchmarks ---

func BenchmarkBuild_1000Groups_1000Leaves(b *testing.B) {
	groups := make(map[string][]Hash, 1000)
	for g := 0; g < 1000; g++ {
		leaves := make([]Hash, 1000)
		for l := 0; l < 1000; l++ {
			leaves[l] = benchHash(fmt.Sprintf("g%d-l%d", g, l))
		}
		groups[fmt.Sprintf("group%d", g)] = leaves
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Build(groups)
	}
}

// --- DiffLeaves benchmark ---

func BenchmarkDiffLeaves_1000Leaves_10Changed(b *testing.B) {
	oldGroups := map[string][]Hash{"pkg": make([]Hash, 1000)}
	newGroups := map[string][]Hash{"pkg": make([]Hash, 1000)}
	for i := 0; i < 1000; i++ {
		oldGroups["pkg"][i] = benchHash(fmt.Sprintf("leaf%d", i))
		if i < 10 {
			newGroups["pkg"][i] = benchHash(fmt.Sprintf("changed%d", i))
		} else {
			newGroups["pkg"][i] = benchHash(fmt.Sprintf("leaf%d", i))
		}
	}
	old := Build(oldGroups)
	new := Build(newGroups)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DiffLeaves(old, new, "pkg")
	}
}

// --- MultiLevel diff benchmark ---

func BenchmarkDiffMultiLevel_50Groups(b *testing.B) {
	old := buildBenchMultiLevel(50, 5, 20)
	// Build new with one subgroup changed.
	var inputs []MultiLevelInput
	for g := 0; g < 50; g++ {
		for sg := 0; sg < 5; sg++ {
			for l := 0; l < 20; l++ {
				leaf := fmt.Sprintf("g%d-sg%d-l%d", g, sg, l)
				if g == 25 && sg == 2 && l == 0 {
					leaf = "changed"
				}
				inputs = append(inputs, MultiLevelInput{
					Leaf:     benchHash(leaf),
					Group:    fmt.Sprintf("group%d", g),
					Subgroup: fmt.Sprintf("subgroup%d", sg),
				})
			}
		}
	}
	new := BuildMultiLevel(inputs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DiffMultiLevelTrees(old, new)
	}
}

// --- SubgraphRoot MultiLevel benchmark ---

func BenchmarkSubgraphRoot_MultiLevel_10of50(b *testing.B) {
	ml := buildBenchMultiLevel(50, 5, 20)
	subset := []string{"group5", "group10", "group15", "group20", "group25",
		"group30", "group35", "group40", "group45", "group49"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ml.SubgraphRoot(subset)
	}
}

// --- Proof size measurement ---

func BenchmarkProofSize(b *testing.B) {
	f := buildBenchForest(100, 1000)
	leaf := f.Leaves("group50")[500]
	proof, _ := f.Prove("group50", leaf)

	// Count proof steps (each step is 32 bytes sibling + 1 byte direction).
	steps := len(proof.LeafPath) + len(proof.GroupPath)
	proofBytes := 32 + // leaf
		len(proof.Group) + // group name
		(steps * 33) + // steps (32 byte hash + 1 byte isLeft)
		32 + // group root
		32 // root
	b.ReportMetric(float64(proofBytes), "bytes/proof")
	b.ReportMetric(float64(steps), "steps/proof")

	for i := 0; i < b.N; i++ {
		Verify(proof, f.Root)
	}
}

func BenchmarkMultiLevelProofSize(b *testing.B) {
	ml := buildBenchMultiLevel(50, 5, 20)
	leaf := benchHash("g25-sg2-l10")
	proof, _ := ml.Prove("group25", "subgroup2", leaf)

	steps := len(proof.LeafPath) + len(proof.SubgroupPath) + len(proof.GroupPath)
	proofBytes := 32 + // leaf
		len(proof.Group) + len(proof.Subgroup) + // names
		(steps * 33) + // steps
		32 + // subgroup root
		32 + // group root
		32 // root
	b.ReportMetric(float64(proofBytes), "bytes/proof")
	b.ReportMetric(float64(steps), "steps/proof")

	for i := 0; i < b.N; i++ {
		VerifyMultiLevel(proof, ml.Root)
	}
}
