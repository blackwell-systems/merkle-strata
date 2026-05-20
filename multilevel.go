package merkleforest

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// MultiLevel is a 3-level stratified Merkle tree: root -> groups -> subgroups -> leaves.
// This models hierarchies like: repo -> packages -> edge-types -> edges.
type MultiLevel struct {
	// Root is the top-level Merkle root.
	Root Hash

	// GroupRoots maps group name to its intermediate root.
	GroupRoots map[string]Hash

	// SubgroupRoots maps "group:subgroup" to its root.
	SubgroupRoots map[string]Hash

	// GroupLeafCounts tracks leaf count per group.
	GroupLeafCounts map[string]int

	// TotalLeaves is the total leaf count.
	TotalLeaves int

	// prefix for interior nodes.
	prefix []byte

	// hashFunc for interior node computation.
	hashFunc HashFunc

	// internal: the underlying forest for proof generation.
	// Subgroups are the actual leaf-bearing groups.
	inner *Forest
}

// MultiLevelInput is a leaf with its group and subgroup metadata.
type MultiLevelInput struct {
	Leaf     Hash
	Group    string // e.g. package path
	Subgroup string // e.g. edge type
}

// BuildMultiLevel constructs a 3-level tree from inputs.
//
// Structure:
//
//	root = merkle(sorted group roots)
//	  group root = merkle(sorted subgroup roots for this group)
//	    subgroup root = merkle(sorted leaf hashes in this subgroup)
//	      leaf
func BuildMultiLevel(inputs []MultiLevelInput, opts ...Option) *MultiLevel {
	cfg := &options{prefix: defaultPrefix, hashFunc: sha256.New}
	for _, o := range opts {
		o(cfg)
	}

	if len(inputs) == 0 {
		return &MultiLevel{
			Root:            Hash{},
			GroupRoots:      map[string]Hash{},
			SubgroupRoots:   map[string]Hash{},
			GroupLeafCounts: map[string]int{},
			prefix:          cfg.prefix,
			hashFunc:        cfg.hashFunc,
		}
	}

	// Group leaves by "group:subgroup".
	byKey := make(map[string][]Hash)
	groupLeafCounts := make(map[string]int)

	for _, inp := range inputs {
		group := inp.Group
		if group == "" {
			group = "_root"
		}
		key := group + ":" + inp.Subgroup
		byKey[key] = append(byKey[key], inp.Leaf)
		groupLeafCounts[group]++
	}

	// Build subgroup roots.
	subgroupRoots := make(map[string]Hash, len(byKey))
	for key, hashes := range byKey {
		sortHashes(hashes)
		subgroupRoots[key] = computeRoot(hashes, cfg.prefix, cfg.hashFunc)
	}

	// Group subgroup roots by group.
	groupSubRoots := make(map[string][]Hash)
	for key, root := range subgroupRoots {
		group := key[:strings.LastIndex(key, ":")]
		groupSubRoots[group] = append(groupSubRoots[group], root)
	}

	// Build group roots.
	groupRoots := make(map[string]Hash, len(groupSubRoots))
	for group, roots := range groupSubRoots {
		sortHashes(roots)
		groupRoots[group] = computeRoot(roots, cfg.prefix, cfg.hashFunc)
	}

	// Build top-level root from group roots sorted by hash bytes.
	// This matches standard Merkle tree construction (sort by content, not label).
	rootHashes := make([]Hash, 0, len(groupRoots))
	for _, root := range groupRoots {
		rootHashes = append(rootHashes, root)
	}
	sortHashes(rootHashes)
	topRoot := computeRoot(rootHashes, cfg.prefix, cfg.hashFunc)

	// Build inner forest using "group:subgroup" as group keys for proof generation.
	innerGroups := make(map[string][]Hash, len(byKey))
	for key, hashes := range byKey {
		innerGroups[key] = hashes
	}
	inner := Build(innerGroups, WithPrefix(cfg.prefix), WithHash(cfg.hashFunc))

	return &MultiLevel{
		Root:            topRoot,
		GroupRoots:      groupRoots,
		SubgroupRoots:   subgroupRoots,
		GroupLeafCounts: groupLeafCounts,
		TotalLeaves:     len(inputs),
		prefix:          cfg.prefix,
		hashFunc:        cfg.hashFunc,
		inner:           inner,
	}
}

// SubgraphRoot computes a root for a subset of groups (not subgroups).
// This is the cache key for "did anything in these groups change?"
func (ml *MultiLevel) SubgraphRoot(groups []string) Hash {
	var roots []Hash
	for _, g := range groups {
		if root, ok := ml.GroupRoots[g]; ok {
			roots = append(roots, root)
		}
	}
	if len(roots) == 0 {
		return Hash{}
	}
	sortHashes(roots)
	return computeRoot(roots, ml.prefix, ml.hashFunc)
}

// MultiLevelProof is a 3-level proof: leaf -> subgroup root -> group root -> root.
type MultiLevelProof struct {
	Leaf         Hash   `json:"leaf"`
	Group        string `json:"group"`
	Subgroup     string `json:"subgroup"`
	LeafPath     []Step `json:"leaf_path"`     // leaf -> subgroup root
	SubgroupRoot Hash   `json:"subgroup_root"`
	SubgroupPath []Step `json:"subgroup_path"` // subgroup root -> group root
	GroupRoot    Hash   `json:"group_root"`
	GroupPath    []Step `json:"group_path"`    // group root -> top root
	Root         Hash   `json:"root"`
}

// Prove generates a 3-level inclusion proof.
func (ml *MultiLevel) Prove(group, subgroup string, leaf Hash) (*MultiLevelProof, error) {
	key := group + ":" + subgroup

	sgRoot, ok := ml.SubgroupRoots[key]
	if !ok {
		return nil, fmt.Errorf("subgroup %q not found", key)
	}

	gRoot, ok := ml.GroupRoots[group]
	if !ok {
		return nil, fmt.Errorf("group %q not found", group)
	}

	// Level 1: leaf -> subgroup root.
	// Get leaves for this subgroup from the inner forest.
	leaves := ml.inner.Leaves(key)
	if leaves == nil {
		return nil, fmt.Errorf("no leaves for subgroup %q", key)
	}
	leafPath, err := binaryProof(leaves, leaf, ml.prefix)
	if err != nil {
		return nil, fmt.Errorf("leaf proof: %w", err)
	}

	// Level 2: subgroup root -> group root.
	// Collect subgroup roots for this group.
	var sgRoots []Hash
	for k, root := range ml.SubgroupRoots {
		if strings.HasPrefix(k, group+":") {
			sgRoots = append(sgRoots, root)
		}
	}
	sortHashes(sgRoots)
	sgPath, err := binaryProof(sgRoots, sgRoot, ml.prefix)
	if err != nil {
		return nil, fmt.Errorf("subgroup proof: %w", err)
	}

	// Level 3: group root -> top root.
	// Group roots are sorted by hash bytes (matching BuildMultiLevel's top-level construction).
	var gRoots []Hash
	for _, root := range ml.GroupRoots {
		gRoots = append(gRoots, root)
	}
	sortHashes(gRoots)
	gPath, err := binaryProof(gRoots, gRoot, ml.prefix)
	if err != nil {
		return nil, fmt.Errorf("group proof: %w", err)
	}

	return &MultiLevelProof{
		Leaf:         leaf,
		Group:        group,
		Subgroup:     subgroup,
		LeafPath:     leafPath,
		SubgroupRoot: sgRoot,
		SubgroupPath: sgPath,
		GroupRoot:    gRoot,
		GroupPath:    gPath,
		Root:         ml.Root,
	}, nil
}

// MultiLevelAbsenceProof proves a leaf does NOT exist in a subgroup.
type MultiLevelAbsenceProof struct {
	Missing  Hash   `json:"missing"`
	Group    string `json:"group"`
	Subgroup string `json:"subgroup"`

	Left       *Hash            `json:"left,omitempty"`
	Right      *Hash            `json:"right,omitempty"`
	LeftProof  *MultiLevelProof `json:"left_proof,omitempty"`
	RightProof *MultiLevelProof `json:"right_proof,omitempty"`

	Root Hash `json:"root"`
}

// ProveAbsent generates a 3-level absence proof that leaf does NOT exist
// in the given group and subgroup.
func (ml *MultiLevel) ProveAbsent(group, subgroup string, leaf Hash) (*MultiLevelAbsenceProof, error) {
	key := group + ":" + subgroup

	if _, ok := ml.SubgroupRoots[key]; !ok {
		// Subgroup doesn't exist: trivial absence.
		return &MultiLevelAbsenceProof{
			Missing:  leaf,
			Group:    group,
			Subgroup: subgroup,
			Root:     ml.Root,
		}, nil
	}

	// Get leaves for this subgroup.
	leaves := ml.inner.Leaves(key)
	if leaves == nil {
		return &MultiLevelAbsenceProof{
			Missing:  leaf,
			Group:    group,
			Subgroup: subgroup,
			Root:     ml.Root,
		}, nil
	}

	// Check leaf isn't present.
	for _, h := range leaves {
		if h == leaf {
			return nil, fmt.Errorf("cannot prove absence: leaf exists in %s", key)
		}
	}

	// Find insertion point.
	idx := sort.Search(len(leaves), func(i int) bool {
		return bytes.Compare(leaves[i][:], leaf[:]) >= 0
	})

	proof := &MultiLevelAbsenceProof{
		Missing:  leaf,
		Group:    group,
		Subgroup: subgroup,
		Root:     ml.Root,
	}

	if idx > 0 {
		left := leaves[idx-1]
		proof.Left = &left
		lp, err := ml.Prove(group, subgroup, left)
		if err != nil {
			return nil, fmt.Errorf("left neighbor proof: %w", err)
		}
		proof.LeftProof = lp
	}

	if idx < len(leaves) {
		right := leaves[idx]
		proof.Right = &right
		rp, err := ml.Prove(group, subgroup, right)
		if err != nil {
			return nil, fmt.Errorf("right neighbor proof: %w", err)
		}
		proof.RightProof = rp
	}

	return proof, nil
}

// VerifyMultiLevelAbsent checks a 3-level absence proof.
func VerifyMultiLevelAbsent(proof *MultiLevelAbsenceProof, root Hash) bool {
	return VerifyMultiLevelAbsentWithPrefix(proof, root, defaultPrefix)
}

// VerifyMultiLevelAbsentWithPrefix checks a 3-level absence proof with a custom prefix.
func VerifyMultiLevelAbsentWithPrefix(proof *MultiLevelAbsenceProof, root Hash, prefix []byte) bool {
	if proof == nil {
		return false
	}

	if proof.LeftProof != nil {
		if !VerifyMultiLevelWithPrefix(proof.LeftProof, root, prefix) {
			return false
		}
		if proof.Left == nil || bytes.Compare(proof.Left[:], proof.Missing[:]) >= 0 {
			return false
		}
	}

	if proof.RightProof != nil {
		if !VerifyMultiLevelWithPrefix(proof.RightProof, root, prefix) {
			return false
		}
		if proof.Right == nil || bytes.Compare(proof.Right[:], proof.Missing[:]) <= 0 {
			return false
		}
	}

	return true
}

// VerifyMultiLevel checks a 3-level proof by recomputing each level.
func VerifyMultiLevel(proof *MultiLevelProof, root Hash) bool {
	return VerifyMultiLevelWithPrefix(proof, root, defaultPrefix)
}

// VerifyMultiLevelWithPrefix checks a 3-level proof with a custom prefix.
func VerifyMultiLevelWithPrefix(proof *MultiLevelProof, root Hash, prefix []byte) bool {
	if proof == nil {
		return false
	}

	// Level 1: leaf -> subgroup root.
	computed := proof.Leaf
	for _, step := range proof.LeafPath {
		if step.IsLeft {
			computed = combineWithPrefix(step.Sibling, computed, prefix)
		} else {
			computed = combineWithPrefix(computed, step.Sibling, prefix)
		}
	}
	if computed != proof.SubgroupRoot {
		return false
	}

	// Level 2: subgroup root -> group root.
	computed = proof.SubgroupRoot
	for _, step := range proof.SubgroupPath {
		if step.IsLeft {
			computed = combineWithPrefix(step.Sibling, computed, prefix)
		} else {
			computed = combineWithPrefix(computed, step.Sibling, prefix)
		}
	}
	if computed != proof.GroupRoot {
		return false
	}

	// Level 3: group root -> top root.
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

// DiffMultiLevel compares two multi-level trees.
type MultiLevelDiff struct {
	ChangedGroups    []string // groups whose root changed
	AddedGroups      []string // groups in new but not old
	RemovedGroups    []string // groups in old but not new
	ChangedSubgroups []string // "group:subgroup" keys whose root changed
	RootChanged      bool
}

// DiffMultiLevel compares two multi-level trees at each level.
func DiffMultiLevelTrees(old, new *MultiLevel) *MultiLevelDiff {
	diff := &MultiLevelDiff{}
	if old == nil {
		old = &MultiLevel{GroupRoots: map[string]Hash{}, SubgroupRoots: map[string]Hash{}}
	}
	if new == nil {
		new = &MultiLevel{GroupRoots: map[string]Hash{}, SubgroupRoots: map[string]Hash{}}
	}

	diff.RootChanged = old.Root != new.Root
	if !diff.RootChanged {
		return diff
	}

	// Compare group roots.
	for name, newRoot := range new.GroupRoots {
		oldRoot, exists := old.GroupRoots[name]
		if !exists {
			diff.AddedGroups = append(diff.AddedGroups, name)
		} else if oldRoot != newRoot {
			diff.ChangedGroups = append(diff.ChangedGroups, name)
		}
	}
	for name := range old.GroupRoots {
		if _, exists := new.GroupRoots[name]; !exists {
			diff.RemovedGroups = append(diff.RemovedGroups, name)
		}
	}

	// Compare subgroup roots (only for changed/added groups).
	changedSet := make(map[string]bool)
	for _, g := range diff.ChangedGroups {
		changedSet[g] = true
	}
	for _, g := range diff.AddedGroups {
		changedSet[g] = true
	}

	for key, newRoot := range new.SubgroupRoots {
		group := key[:strings.LastIndex(key, ":")]
		if !changedSet[group] {
			continue
		}
		oldRoot, exists := old.SubgroupRoots[key]
		if !exists || oldRoot != newRoot {
			diff.ChangedSubgroups = append(diff.ChangedSubgroups, key)
		}
	}

	sort.Strings(diff.ChangedGroups)
	sort.Strings(diff.AddedGroups)
	sort.Strings(diff.RemovedGroups)
	sort.Strings(diff.ChangedSubgroups)

	return diff
}
