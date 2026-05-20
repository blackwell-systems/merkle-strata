<p align="center">
  <a href="https://github.com/blackwell-systems"><img src="https://raw.githubusercontent.com/blackwell-systems/blackwell-docs-theme/main/badge-trademark.svg" alt="Blackwell Systems"></a>
  <a href="https://pkg.go.dev/github.com/blackwell-systems/merkle-forest"><img src="https://pkg.go.dev/badge/github.com/blackwell-systems/merkle-forest.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

---

Standard Merkle trees are flat. Real data has structure.

**merkle-forest** builds stratified Merkle trees where groups of leaves share intermediate roots. This enables operations flat trees can't express:

- **O(groups) diff** instead of O(leaves): "which groups changed?" is a root comparison
- **Absence proofs**: prove something does NOT exist (via adjacent sorted leaves)
- **Scoped queries**: compute a root for any subset of groups without materializing the rest
- **Inclusion proofs**: standard Merkle path from leaf to root, through group intermediate roots

Zero dependencies. Stdlib only.

```go
import forest "github.com/blackwell-systems/merkle-forest"
```

## Quick Start

```go
// Build a forest from grouped data.
// Each group has a name and a set of leaf hashes.
groups := map[string][][32]byte{
    "users":    {hash("user.Create"), hash("user.Delete"), hash("user.Update")},
    "billing":  {hash("billing.Charge"), hash("billing.Refund")},
    "auth":     {hash("auth.Login"), hash("auth.Logout"), hash("auth.Refresh")},
}

f := forest.Build(groups)
// f.Root is the single Merkle root covering all groups.

// Prove a leaf exists.
proof, err := f.Prove("auth", hash("auth.Login"))
// proof verifies offline: leaf -> group root -> forest root

// Verify the proof (no tree needed, just the proof + root).
valid := forest.Verify(proof, f.Root)

// Prove a leaf does NOT exist.
absent, err := f.ProveAbsent("auth", hash("auth.Revoke"))
valid = forest.VerifyAbsent(absent, f.Root)

// Scoped root: compute a root for a subset of groups.
// Useful for caching: "did anything in these groups change?"
subRoot := f.SubRoot([]string{"users", "auth"})

// Diff two forests: which groups changed?
added, removed, changed := forest.Diff(oldForest, newForest)
// changed contains only the group names whose roots differ.
// No need to compare individual leaves to detect changes.
```

## Why This Exists

| Library | Structure | Absence proofs | Group diff | Scoped queries |
|---|---|---|---|---|
| cbergoon/merkletree | Flat | No | No | No |
| txaty/go-merkletree | Flat (parallel) | No | No | No |
| celestiaorg/nmt | Namespaced (1 level) | No (range proofs) | No | No |
| celestiaorg/smt | Sparse (key-indexed) | Yes (empty leaf) | No | No |
| **merkle-forest** | **Stratified (N groups)** | **Yes (gap proof)** | **Yes (O(groups))** | **Yes (SubRoot)** |

Namespaced Merkle Trees (NMT) group by a single namespace dimension. Sparse Merkle Trees (SMT) give absence by construction but are key-indexed with fixed depth. merkle-forest groups by arbitrary string keys with variable leaf counts per group, and proves absence via sorted adjacency (no empty-leaf overhead).

## API

### Build

```go
// Build constructs a forest from grouped leaves.
// Leaves within each group are sorted lexicographically.
// Groups are combined into a top-level Merkle tree (sorted by group root).
func Build(groups map[string][][32]byte) *Forest
```

### Proofs

```go
// Prove generates an inclusion proof: leaf exists in group, group exists in forest.
func (f *Forest) Prove(group string, leaf [32]byte) (*Proof, error)

// Verify checks an inclusion proof against a root hash.
func Verify(proof *Proof, root [32]byte) bool

// ProveAbsent generates an absence proof: leaf does NOT exist in group.
// Uses adjacent sorted leaves to prove the gap.
func (f *Forest) ProveAbsent(group string, leaf [32]byte) (*AbsenceProof, error)

// VerifyAbsent checks an absence proof against a root hash.
func VerifyAbsent(proof *AbsenceProof, root [32]byte) bool
```

### Queries

```go
// SubRoot computes a Merkle root for a subset of groups.
// Useful for scoped cache keys: "did anything in these groups change?"
func (f *Forest) SubRoot(groups []string) [32]byte

// GroupRoot returns the intermediate root for a single group.
func (f *Forest) GroupRoot(group string) ([32]byte, bool)
```

### Diff

```go
// Diff compares two forests and returns which groups were added, removed, or changed.
// O(groups), not O(leaves). Compares intermediate roots only.
func Diff(old, new *Forest) (added, removed, changed []string)
```

## Performance

Built for datasets where the number of groups is moderate (10s to 1000s) and leaves per group vary. The hierarchical structure means:

- **Building**: O(N log N) where N is total leaves (sort per group + group tree)
- **Proof generation**: O(log G + log L) where G is groups and L is leaves in the target group
- **Proof verification**: O(log G + log L) hash computations
- **Diff**: O(G) root comparisons (skips unchanged groups entirely)
- **SubRoot**: O(S log S) where S is the subset size

## Proof Format

Proofs are self-contained JSON-serializable structures:

```go
type Proof struct {
    Leaf      [32]byte    `json:"leaf"`
    Group     string      `json:"group"`
    LeafPath  []Step      `json:"leaf_path"`   // leaf -> group root
    GroupRoot [32]byte    `json:"group_root"`
    GroupPath []Step      `json:"group_path"`  // group root -> forest root
    Root      [32]byte    `json:"root"`
}

type Step struct {
    Sibling [32]byte `json:"sibling"`
    IsLeft  bool     `json:"is_left"`
}
```

Absence proofs include the two adjacent leaves that bracket the missing hash, plus inclusion proofs for both neighbors.

## Design Choices

- **Sorted leaves**: Leaves within a group are sorted by `bytes.Compare`. This enables absence proofs (binary search for gap) and deterministic roots (same set = same root regardless of insertion order).
- **Domain-prefixed internal nodes**: Interior hashes use `SHA-256("merkle-forest\0" || left || right)` to prevent leaf/node confusion and cross-tree collisions.
- **No dependencies**: Uses only `crypto/sha256`, `bytes`, `sort`, `fmt` from stdlib.
- **Immutable**: `Build` returns a frozen structure. Mutate the input and rebuild (trees are cheap to construct).

## Use Cases

- **Code intelligence**: Group edges by package, prove a relationship exists at a snapshot, detect which packages changed
- **Audit trails**: Prove an event occurred (or didn't) in a log partitioned by category
- **Configuration management**: Group settings by service, detect which services' configs changed
- **Supply chain**: Group dependencies by source, prove a specific version was (or wasn't) included
- **Multi-tenant storage**: Group records by tenant, generate per-tenant roots for isolated verification

## Extracted From

merkle-forest is extracted from [knowing](https://github.com/blackwell-systems/knowing), an intelligence versioning system that uses stratified Merkle trees for code relationship proofs, scoped cache invalidation, and feedback expiration.

## License

MIT
