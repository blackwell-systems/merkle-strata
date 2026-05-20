package merkleforest

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"sort"
)

// Hash is a 32-byte SHA-256 hash.
type Hash = [32]byte

// defaultPrefix is prepended to interior node hashes to prevent leaf/node
// confusion and cross-structure collisions.
var defaultPrefix = []byte("merkle-forest\x00")

// HashFunc is a function that returns a new hash.Hash instance.
// Used to configure the hash algorithm for tree construction.
type HashFunc func() hash.Hash

// Option configures forest construction.
type Option func(*options)

type options struct {
	prefix   []byte
	hashFunc HashFunc
}

// WithPrefix sets a custom domain prefix for interior node hashes.
// Use this for backward compatibility when migrating from an existing
// Merkle tree implementation that uses a different prefix.
func WithPrefix(prefix []byte) Option {
	return func(o *options) {
		o.prefix = prefix
	}
}

// WithHash sets a custom hash function for tree construction.
// The function must return a hash.Hash that produces 32-byte digests.
// Default is crypto/sha256. Use this for BLAKE3, SHA-512/256, or
// other 32-byte hash functions.
func WithHash(fn HashFunc) Option {
	return func(o *options) {
		o.hashFunc = fn
	}
}

// Forest is an immutable stratified Merkle tree built from grouped leaves.
type Forest struct {
	// Root is the top-level Merkle root covering all groups.
	Root Hash

	// groups maps group name to its sorted leaves and computed root.
	groups map[string]*group

	// groupRoots is the sorted list of group roots (used for top-level tree).
	groupRoots []Hash

	// groupNames maps group root hash to group name (for reverse lookup in diff).
	groupNames map[Hash]string

	// prefix used for interior node hashes.
	prefix []byte

	// hashFunc for interior node computation.
	hashFunc HashFunc
}

type group struct {
	name   string
	leaves []Hash
	root   Hash
}

// Build constructs a forest from grouped leaves. Leaves within each group are
// sorted lexicographically by bytes.Compare. Groups are combined into a
// top-level Merkle tree sorted by group root hash.
//
// Options can override the domain prefix (default: "merkle-forest\0").
func Build(groups map[string][]Hash, opts ...Option) *Forest {
	cfg := &options{prefix: defaultPrefix, hashFunc: sha256.New}
	for _, o := range opts {
		o(cfg)
	}

	if len(groups) == 0 {
		return &Forest{Root: Hash{}, groups: map[string]*group{}, prefix: cfg.prefix, hashFunc: cfg.hashFunc}
	}

	f := &Forest{
		groups:     make(map[string]*group, len(groups)),
		groupNames: make(map[Hash]string, len(groups)),
		prefix:     cfg.prefix,
		hashFunc:   cfg.hashFunc,
	}

	for name, leaves := range groups {
		sorted := make([]Hash, len(leaves))
		copy(sorted, leaves)
		sortHashes(sorted)

		root := computeRoot(sorted, f.prefix, f.hashFunc)
		g := &group{name: name, leaves: sorted, root: root}
		f.groups[name] = g
		f.groupNames[root] = name
	}

	// Build top-level tree from sorted group roots.
	f.groupRoots = make([]Hash, 0, len(f.groups))
	for _, g := range f.groups {
		f.groupRoots = append(f.groupRoots, g.root)
	}
	sortHashes(f.groupRoots)
	f.Root = computeRoot(f.groupRoots, f.prefix, f.hashFunc)

	return f
}

// GroupRoot returns the intermediate Merkle root for a single group.
// Returns false if the group does not exist.
func (f *Forest) GroupRoot(name string) (Hash, bool) {
	g, ok := f.groups[name]
	if !ok {
		return Hash{}, false
	}
	return g.root, true
}

// Groups returns the list of group names in the forest.
func (f *Forest) Groups() []string {
	names := make([]string, 0, len(f.groups))
	for name := range f.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Leaves returns the sorted leaf hashes for a group.
// Returns nil if the group does not exist.
func (f *Forest) Leaves(name string) []Hash {
	g, ok := f.groups[name]
	if !ok {
		return nil
	}
	out := make([]Hash, len(g.leaves))
	copy(out, g.leaves)
	return out
}

// LeafCount returns the total number of leaves across all groups.
func (f *Forest) LeafCount() int {
	total := 0
	for _, g := range f.groups {
		total += len(g.leaves)
	}
	return total
}

// GroupLeafCount returns the number of leaves in a specific group.
// Returns 0 if the group does not exist.
func (f *Forest) GroupLeafCount(name string) int {
	g, ok := f.groups[name]
	if !ok {
		return 0
	}
	return len(g.leaves)
}

// SubRoot computes a Merkle root for a subset of groups. Useful for scoped
// cache keys: "did anything in these groups change?" Returns the empty hash
// if none of the groups exist.
func (f *Forest) SubRoot(groups []string) Hash {
	var roots []Hash
	for _, name := range groups {
		if g, ok := f.groups[name]; ok {
			roots = append(roots, g.root)
		}
	}
	if len(roots) == 0 {
		return Hash{}
	}
	sortHashes(roots)
	return computeRoot(roots, f.prefix, f.hashFunc)
}

// --- internal ---

// computeRoot recursively computes a binary Merkle root from sorted hashes.
func computeRoot(hashes []Hash, prefix []byte, hf HashFunc) Hash {
	if len(hashes) == 0 {
		return Hash{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	var next []Hash
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			next = append(next, combine(hashes[i], hashes[i+1], prefix, hf))
		} else {
			next = append(next, combine(hashes[i], hashes[i], prefix, hf))
		}
	}
	return computeRoot(next, prefix, hf)
}

// combine produces a parent hash from two children using domain-prefixed hashing.
func combine(left, right Hash, prefix []byte, hf HashFunc) Hash {
	h := hf()
	h.Write(prefix)
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// computeRootWithPrefix is a convenience for code that doesn't have a HashFunc (uses SHA-256).
func computeRootWithPrefix(hashes []Hash, prefix []byte) Hash {
	return computeRoot(hashes, prefix, sha256.New)
}

// combineWithPrefix is a convenience for verification code that doesn't store a HashFunc.
func combineWithPrefix(left, right Hash, prefix []byte) Hash {
	return combine(left, right, prefix, sha256.New)
}

// SortHashes sorts a slice of hashes lexicographically by bytes.Compare.
func SortHashes(hashes []Hash) {
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i][:], hashes[j][:]) < 0
	})
}

// sortHashes is the internal alias.
func sortHashes(hashes []Hash) { SortHashes(hashes) }
