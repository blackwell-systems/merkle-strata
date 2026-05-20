<p align="center">
  <img src="assets/banner.jpg" alt="merkle-forest" width="800">
</p>

<p align="center">
  <a href="https://github.com/blackwell-systems"><img src="https://raw.githubusercontent.com/blackwell-systems/blackwell-docs-theme/main/badge-trademark.svg" alt="Blackwell Systems"></a>
  <a href="https://pkg.go.dev/github.com/blackwell-systems/merkle-forest"><img src="https://pkg.go.dev/badge/github.com/blackwell-systems/merkle-forest.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="#parity"><img src="https://img.shields.io/badge/tests-39_passing-brightgreen.svg" alt="Tests"></a>
</p>

---

Standard Merkle trees are flat. Real data has structure.

**merkle-forest** builds stratified Merkle trees where groups of leaves share intermediate roots. Prove something exists. Prove something doesn't. Detect which groups changed without scanning leaves. Query any subtree without loading the rest.

```go
import forest "github.com/blackwell-systems/merkle-forest"
```

Zero dependencies. Stdlib only. `go get github.com/blackwell-systems/merkle-forest`

---

## In 30 Seconds

```go
f := forest.Build(map[string][][32]byte{
    "users":   {hash("user.Create"), hash("user.Delete")},
    "billing": {hash("billing.Charge"), hash("billing.Refund")},
    "auth":    {hash("auth.Login"), hash("auth.Logout")},
})

// One root covers everything.
fmt.Printf("root: %x\n", f.Root)

// Prove a leaf exists (offline-verifiable).
proof, _ := f.Prove("auth", hash("auth.Login"))
forest.Verify(proof, f.Root) // true

// Prove a leaf does NOT exist.
absent, _ := f.ProveAbsent("auth", hash("auth.Revoke"))
forest.VerifyAbsent(absent, f.Root) // true

// Which groups changed?
added, removed, changed := forest.Diff(oldForest, newForest)

// Cache key for a subset of groups.
subRoot := f.SubRoot([]string{"users", "auth"})
```

---

## Two Modes

### Forest (2-level: root -> groups -> leaves)

For simple grouped data. One level of structure.

```go
f := forest.Build(groups)
f.Prove("group", leaf)
f.ProveAbsent("group", leaf)
f.SubRoot([]string{"group1", "group2"})
forest.Diff(old, new)
```

### MultiLevel (3-level: root -> groups -> subgroups -> leaves)

For hierarchical data. Two levels of structure (e.g. packages containing edge types containing edges).

```go
ml := forest.BuildMultiLevel([]forest.MultiLevelInput{
    {Leaf: hash("e1"), Group: "pkg/auth", Subgroup: "calls"},
    {Leaf: hash("e2"), Group: "pkg/auth", Subgroup: "imports"},
    {Leaf: hash("e3"), Group: "pkg/store", Subgroup: "calls"},
})

// 3-level proof: leaf -> subgroup root -> group root -> top root.
proof, _ := ml.Prove("pkg/auth", "calls", hash("e1"))
forest.VerifyMultiLevel(proof, ml.Root)

// Which groups changed? Which subgroups within them?
diff := forest.DiffMultiLevelTrees(oldML, newML)
// diff.ChangedGroups: ["pkg/store"]
// diff.ChangedSubgroups: ["pkg/store:calls"]

// Cache key for a subset of groups.
subRoot := ml.SubgraphRoot([]string{"pkg/auth"})
```

---

## Why This Exists

| Library | Structure | Absence proofs | Group diff | Scoped queries |
|---|---|---|---|---|
| cbergoon/merkletree | Flat | No | No | No |
| txaty/go-merkletree | Flat (parallel) | No | No | No |
| celestiaorg/nmt | Namespaced (1 level) | No (range) | No | No |
| celestiaorg/smt | Sparse (key-indexed) | Yes (empty leaf) | No | No |
| **merkle-forest** | **Stratified (2 or 3 level)** | **Yes (gap proof)** | **Yes (O(groups))** | **Yes** |

NMT groups by a single namespace. SMT gives absence by construction but uses fixed-depth key-space indexing. merkle-forest groups by arbitrary string keys, supports variable leaf counts per group, and proves absence via sorted adjacency without empty-leaf overhead.

---

## Full API

### Building

```go
// 2-level: groups of leaves.
func Build(groups map[string][]Hash, opts ...Option) *Forest

// 3-level: groups of subgroups of leaves.
func BuildMultiLevel(inputs []MultiLevelInput, opts ...Option) *MultiLevel

// Custom domain prefix (for backward compat with existing systems).
forest.Build(groups, forest.WithPrefix([]byte("merkle\x00")))
```

### Inclusion Proofs

```go
// 2-level.
func (f *Forest) Prove(group string, leaf Hash) (*Proof, error)
func Verify(proof *Proof, root Hash) bool
func VerifyWithPrefix(proof *Proof, root Hash, prefix []byte) bool

// 3-level.
func (ml *MultiLevel) Prove(group, subgroup string, leaf Hash) (*MultiLevelProof, error)
func VerifyMultiLevel(proof *MultiLevelProof, root Hash) bool
func VerifyMultiLevelWithPrefix(proof *MultiLevelProof, root Hash, prefix []byte) bool
```

### Absence Proofs

```go
func (f *Forest) ProveAbsent(group string, leaf Hash) (*AbsenceProof, error)
func VerifyAbsent(proof *AbsenceProof, root Hash) bool
func VerifyAbsentWithPrefix(proof *AbsenceProof, root Hash, prefix []byte) bool
```

### Queries

```go
// Scoped root for cache keys.
func (f *Forest) SubRoot(groups []string) Hash
func (ml *MultiLevel) SubgraphRoot(groups []string) Hash

// Inspect structure.
func (f *Forest) GroupRoot(name string) (Hash, bool)
func (f *Forest) Groups() []string
func (f *Forest) Leaves(group string) []Hash
func (f *Forest) LeafCount() int
func (f *Forest) GroupLeafCount(name string) int
```

### Diff

```go
// Simple diff.
func Diff(old, new *Forest) (added, removed, changed []string)

// With filtering and cap.
func DiffWithOptions(old, new *Forest, opts *DiffOptions) *DiffResult

// Leaf-level diff within a single group.
func DiffLeaves(old, new *Forest, group string) (added, removed []Hash)

// 3-level diff.
func DiffMultiLevelTrees(old, new *MultiLevel) *MultiLevelDiff
```

### Utilities

```go
func SortHashes(hashes []Hash)
```

---

## Performance

| Operation | Complexity | Notes |
|---|---|---|
| Build | O(N log N) | N = total leaves. Sort per group + tree construction. |
| Prove | O(log G + log L) | G = groups, L = leaves in target group. |
| Verify | O(log G + log L) | Hash recomputation only. No tree needed. |
| Diff | O(G) | Compares group roots. Skips unchanged groups entirely. |
| SubRoot | O(S log S) | S = subset size. |
| DiffLeaves | O(L) | For one changed group after Diff identifies it. |

---

## Proof Format

Proofs are self-contained, JSON-serializable, and verifiable offline (no database or tree needed, just the proof bytes and a root hash):

```go
type Proof struct {
    Leaf      [32]byte `json:"leaf"`
    Group     string   `json:"group"`
    LeafPath  []Step   `json:"leaf_path"`   // leaf -> group root
    GroupRoot [32]byte `json:"group_root"`
    GroupPath []Step   `json:"group_path"`  // group root -> forest root
    Root      [32]byte `json:"root"`
}

type MultiLevelProof struct {
    Leaf         [32]byte `json:"leaf"`
    Group        string   `json:"group"`
    Subgroup     string   `json:"subgroup"`
    LeafPath     []Step   `json:"leaf_path"`     // leaf -> subgroup root
    SubgroupRoot [32]byte `json:"subgroup_root"`
    SubgroupPath []Step   `json:"subgroup_path"` // subgroup root -> group root
    GroupRoot    [32]byte `json:"group_root"`
    GroupPath    []Step   `json:"group_path"`    // group root -> top root
    Root         [32]byte `json:"root"`
}
```

Absence proofs include the two adjacent sorted leaves that bracket the gap, plus inclusion proofs for both neighbors. Verifiers confirm: left < missing < right, and both neighbors are in the tree.

---

## Design Choices

**Sorted leaves.** Leaves within a group are sorted by `bytes.Compare`. Same set = same root regardless of insertion order. Enables absence proofs via binary search for gaps.

**Domain-prefixed interior nodes.** `SHA-256("merkle-forest\0" || left || right)` prevents second-preimage attacks and cross-tree collisions. Configurable via `WithPrefix` for systems with existing hash schemes.

**Immutable.** `Build` returns a frozen structure. Rebuild on mutation. Trees are cheap to construct (microseconds for hundreds of groups).

**No dependencies.** `crypto/sha256`, `bytes`, `sort`, `fmt`, `strings`. Nothing else.

---

## Parity

merkle-forest includes a parity test (`parity_test.go`) that manually replicates [knowing](https://github.com/blackwell-systems/knowing)'s internal Merkle tree algorithm step-by-step and verifies byte-identical output at every level:

```
=== RUN   TestParity_HierarchicalTree
    parity_test.go: PARITY VERIFIED: merkle-forest with WithPrefix("merkle\x00")
    produces identical hashes to knowing
--- PASS
```

This guarantees `BuildMultiLevel` with `WithPrefix([]byte("merkle\x00"))` is a drop-in replacement for knowing's `internal/snapshot.BuildHierarchicalTree`.

---

## Use Cases

**Code intelligence.** Group edges by package, prove a relationship exists at a snapshot, detect which packages changed. (This is what [knowing](https://github.com/blackwell-systems/knowing) uses it for.)

**Audit trails.** Prove an event occurred (or didn't) in a log partitioned by category. Offline verification without database access.

**Configuration management.** Group settings by service. `SubRoot(["api", "worker"])` gives a single hash that changes only when those services' configs change.

**Supply chain.** Group dependencies by source. Prove a specific version was or wasn't included at a point in time.

**Multi-tenant storage.** Group records by tenant. Per-tenant roots enable isolated verification without exposing other tenants' data.

---

## License

MIT
