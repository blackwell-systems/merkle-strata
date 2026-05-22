package merklestrata

import (
	"bytes"
	"fmt"
	"sort"
)

// Step represents one step in a Merkle proof path.
type Step struct {
	Sibling Hash `json:"sibling"`
	IsLeft  bool `json:"is_left"` // true if sibling is on the left
}

// Proof is an inclusion proof that a leaf exists in a group within the tree.
// Verification recomputes: leaf -> group root -> tree root.
type Proof struct {
	Leaf      Hash   `json:"leaf"`
	Group     string `json:"group"`
	LeafPath  []Step `json:"leaf_path"`  // leaf -> group root
	GroupRoot Hash   `json:"group_root"`
	GroupPath []Step `json:"group_path"` // group root -> tree root
	Root      Hash   `json:"root"`
}

// AbsenceProof proves that a leaf does NOT exist in a group.
// It proves the two adjacent leaves that bracket the missing hash:
// left < missing < right. Since leaves are sorted, adjacency proves no room.
type AbsenceProof struct {
	Missing Hash   `json:"missing"`
	Group   string `json:"group"`

	// Left is the largest leaf smaller than Missing (nil if Missing would be first).
	Left *Hash `json:"left,omitempty"`
	// Right is the smallest leaf larger than Missing (nil if Missing would be last).
	Right *Hash `json:"right,omitempty"`

	// LeftProof proves Left is in the tree.
	LeftProof *Proof `json:"left_proof,omitempty"`
	// RightProof proves Right is in the tree.
	RightProof *Proof `json:"right_proof,omitempty"`

	Root Hash `json:"root"`
}

// Prove generates an inclusion proof that leaf exists in the named group.
func (f *Tree) Prove(groupName string, leaf Hash) (*Proof, error) {
	g, ok := f.groups[groupName]
	if !ok {
		return nil, fmt.Errorf("group %q not found", groupName)
	}

	// Level 1: prove leaf is in the group's leaf set.
	leafPath, err := binaryProof(g.leaves, leaf, f.prefix)
	if err != nil {
		return nil, fmt.Errorf("leaf proof: %w", err)
	}

	// Level 2: prove group root is in the tree's group root set.
	// Uses binaryProofTree to match computeTreeRoot semantics (domain separation
	// for single-group trees).
	groupPath, err := binaryProofTree(f.groupRoots, g.root, f.prefix)
	if err != nil {
		return nil, fmt.Errorf("group proof: %w", err)
	}

	return &Proof{
		Leaf:      leaf,
		Group:     groupName,
		LeafPath:  leafPath,
		GroupRoot: g.root,
		GroupPath: groupPath,
		Root:      f.Root,
	}, nil
}

// ProveAbsent generates an absence proof that leaf does NOT exist in the named group.
// Returns an error if the leaf IS found (can't prove absence of something present).
func (f *Tree) ProveAbsent(groupName string, leaf Hash) (*AbsenceProof, error) {
	g, ok := f.groups[groupName]
	if !ok {
		// Group doesn't exist: trivial absence.
		return &AbsenceProof{
			Missing: leaf,
			Group:   groupName,
			Root:    f.Root,
		}, nil
	}

	// Check leaf isn't actually present.
	for _, h := range g.leaves {
		if h == leaf {
			return nil, fmt.Errorf("cannot prove absence: leaf exists in group %q", groupName)
		}
	}

	// Find insertion point in sorted leaves.
	idx := sort.Search(len(g.leaves), func(i int) bool {
		return bytes.Compare(g.leaves[i][:], leaf[:]) >= 0
	})

	proof := &AbsenceProof{
		Missing: leaf,
		Group:   groupName,
		Root:    f.Root,
	}

	// Left neighbor.
	if idx > 0 {
		left := g.leaves[idx-1]
		proof.Left = &left
		lp, err := f.Prove(groupName, left)
		if err != nil {
			return nil, fmt.Errorf("left neighbor proof: %w", err)
		}
		proof.LeftProof = lp
	}

	// Right neighbor.
	if idx < len(g.leaves) {
		right := g.leaves[idx]
		proof.Right = &right
		rp, err := f.Prove(groupName, right)
		if err != nil {
			return nil, fmt.Errorf("right neighbor proof: %w", err)
		}
		proof.RightProof = rp
	}

	return proof, nil
}

// Verify checks that an inclusion proof is valid by recomputing the root.
// Uses the default domain prefix. For custom prefixes, use VerifyWithPrefix.
func Verify(proof *Proof, root Hash) bool {
	return VerifyWithPrefix(proof, root, defaultPrefix)
}

// VerifyWithPrefix checks an inclusion proof using a custom domain prefix.
func VerifyWithPrefix(proof *Proof, root Hash, prefix []byte) bool {
	if proof == nil {
		return false
	}

	// Level 1: leaf -> group root.
	computed := proof.Leaf
	for _, step := range proof.LeafPath {
		if step.IsLeft {
			computed = combineWithPrefix(step.Sibling, computed, prefix)
		} else {
			computed = combineWithPrefix(computed, step.Sibling, prefix)
		}
	}
	if computed != proof.GroupRoot {
		return false
	}

	// Level 2: group root -> tree root.
	computed = proof.GroupRoot
	for _, step := range proof.GroupPath {
		if step.IsLeft {
			computed = combineWithPrefix(step.Sibling, computed, prefix)
		} else {
			computed = combineWithPrefix(computed, step.Sibling, prefix)
		}
	}
	return computed == root
}

// VerifyAbsent checks that an absence proof is valid.
// Uses the default domain prefix. For custom prefixes, use VerifyAbsentWithPrefix.
func VerifyAbsent(proof *AbsenceProof, root Hash) bool {
	return VerifyAbsentWithPrefix(proof, root, defaultPrefix)
}

// VerifyAbsentWithPrefix checks an absence proof using a custom domain prefix.
func VerifyAbsentWithPrefix(proof *AbsenceProof, root Hash, prefix []byte) bool {
	if proof == nil {
		return false
	}

	// Verify left neighbor if present.
	if proof.LeftProof != nil {
		if !VerifyWithPrefix(proof.LeftProof, root, prefix) {
			return false
		}
		if proof.Left == nil || bytes.Compare(proof.Left[:], proof.Missing[:]) >= 0 {
			return false
		}
	}

	// Verify right neighbor if present.
	if proof.RightProof != nil {
		if !VerifyWithPrefix(proof.RightProof, root, prefix) {
			return false
		}
		if proof.Right == nil || bytes.Compare(proof.Right[:], proof.Missing[:]) <= 0 {
			return false
		}
	}

	return true
}

// binaryProofTree generates proof steps matching computeTreeRoot semantics.
// For a single-element input, it produces a self-paired step (domain separation
// between a group root and the tree root). For multiple elements, it delegates
// to binaryProof.
func binaryProofTree(leaves []Hash, target Hash, prefix []byte) ([]Step, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("empty leaf set")
	}
	if len(leaves) == 1 {
		if leaves[0] != target {
			return nil, fmt.Errorf("target not found")
		}
		// Single element: computeTreeRoot produces combine(x, x, prefix, hf),
		// so we emit a self-paired step where the sibling is the target itself.
		return []Step{{Sibling: target, IsLeft: false}}, nil
	}
	return binaryProof(leaves, target, prefix)
}

// binaryProof generates proof steps for a target within a sorted leaf set.
func binaryProof(leaves []Hash, target Hash, prefix []byte) ([]Step, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("empty leaf set")
	}
	if len(leaves) == 1 {
		if leaves[0] != target {
			return nil, fmt.Errorf("target not found")
		}
		return nil, nil
	}

	idx := -1
	for i, h := range leaves {
		if h == target {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("target not found in leaf set")
	}

	var steps []Step
	level := make([]Hash, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next []Hash
		nextIdx := -1

		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}

			combined := combineWithPrefix(left, right, prefix)
			next = append(next, combined)

			if i == idx {
				steps = append(steps, Step{Sibling: right, IsLeft: false})
				nextIdx = len(next) - 1
			} else if i+1 == idx {
				steps = append(steps, Step{Sibling: left, IsLeft: true})
				nextIdx = len(next) - 1
			}
		}

		level = next
		idx = nextIdx
	}

	return steps, nil
}
