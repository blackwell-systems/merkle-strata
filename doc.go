// Package merkleforest provides stratified Merkle trees where groups of leaves
// share intermediate roots.
//
// A standard Merkle tree hashes a flat list of leaves into one root. merkleforest
// adds structure: leaves are organized into named groups, each group gets its own
// Merkle subtree, and the group roots are combined into a top-level tree. This
// enables operations that flat trees cannot express efficiently:
//
//   - O(groups) diff: compare two forests by checking group roots, not individual leaves
//   - Absence proofs: prove a leaf does NOT exist using adjacent sorted leaves
//   - Scoped queries: compute a root for any subset of groups (cache keys, partial verification)
//   - Inclusion proofs: standard Merkle path from leaf through group root to forest root
//
// # Two Modes
//
// Forest provides a 2-level tree (root -> groups -> leaves):
//
//	f := merkleforest.Build(map[string][]merkleforest.Hash{
//	    "users":   {hash("user.Create"), hash("user.Delete")},
//	    "billing": {hash("billing.Charge")},
//	})
//	proof, _ := f.Prove("users", hash("user.Create"))
//	merkleforest.Verify(proof, f.Root) // true
//
// MultiLevel provides a 3-level tree (root -> groups -> subgroups -> leaves):
//
//	ml := merkleforest.BuildMultiLevel([]merkleforest.MultiLevelInput{
//	    {Leaf: hash("e1"), Group: "pkg/auth", Subgroup: "calls"},
//	    {Leaf: hash("e2"), Group: "pkg/auth", Subgroup: "imports"},
//	})
//	proof, _ := ml.Prove("pkg/auth", "calls", hash("e1"))
//	merkleforest.VerifyMultiLevel(proof, ml.Root) // true
//
// # Absence Proofs
//
// Prove that a leaf does NOT exist in a group. The proof includes the two adjacent
// sorted leaves that bracket the gap where the missing leaf would be inserted.
// Verifiers confirm both neighbors are in the tree and that they are adjacent
// (no room for the missing leaf between them):
//
//	absent, _ := f.ProveAbsent("users", hash("user.Ban"))
//	merkleforest.VerifyAbsent(absent, f.Root) // true (user.Ban is not in the tree)
//
// # Diff
//
// Compare two forests in O(groups) by checking intermediate roots:
//
//	added, removed, changed := merkleforest.Diff(oldForest, newForest)
//
// Then drill into changed groups for leaf-level detail:
//
//	addedLeaves, removedLeaves := merkleforest.DiffLeaves(oldForest, newForest, "users")
//
// # Custom Domain Prefix
//
// Interior node hashes are computed as SHA-256(prefix || left || right). The default
// prefix is "merkle-forest\x00". Use [WithPrefix] to override for backward compatibility
// with existing Merkle tree implementations:
//
//	f := merkleforest.Build(groups, merkleforest.WithPrefix([]byte("myprefix\x00")))
//
// # Properties
//
//   - Deterministic: same input set (any order) produces the same root
//   - Content-addressed: the root is a function of leaf content, not names or insertion order
//   - Immutable: Build returns a frozen structure; mutate inputs and rebuild
//   - Zero dependencies: uses only crypto/sha256, bytes, sort, fmt, strings from stdlib
//   - Proofs are self-contained: verifiable offline with just the proof bytes and a root hash
package merkleforest
