# Benchmarks

All benchmarks run on Apple M4 Pro, Go 1.23, single invocation with `-benchmem`. Reproduce with:

```bash
go test -bench=. -benchmem -count=1
```

## Build Performance

How fast can you construct a forest from raw data?

| Groups | Leaves/Group | Total Leaves | Time | Allocs |
|---:|---:|---:|---:|---:|
| 10 | 100 | 1,000 | 118us | 280 |
| 100 | 100 | 10,000 | 1.2ms | 2,635 |
| 100 | 1,000 | 100,000 | 14ms | 5,035 |
| 1,000 | 1,000 | 1,000,000 | 145ms | 50,063 |

**MultiLevel** (3-level tree):

| Groups | Subgroups/Group | Leaves/Subgroup | Total Leaves | Time |
|---:|---:|---:|---:|---:|
| 50 | 5 | 20 | 5,000 | 1.4ms |

**Takeaway:** Build scales linearly with total leaves. 1M leaves in 145ms. Single-threaded; the parallel hashing optimization (future) would cut this further at scale.

## Proof Generation

How fast can you generate an inclusion or absence proof?

| Operation | Groups | Leaves/Group | Time | Allocs |
|---|---:|---:|---:|---:|
| Prove (2-level) | 10 | 100 | 8.7us | 46 |
| Prove (2-level) | 100 | 100 | 15.7us | 65 |
| Prove (3-level) | 50x5 subgroups | 20 | 12.3us | 69 |
| ProveAbsent (2-level) | 10 | 100 | 17.8us | 95 |

**Takeaway:** Proof generation is O(log G + log L). Absence proofs cost ~2x inclusion (two neighbor proofs).

## Proof Verification

How fast can you verify a proof offline (no tree needed)?

| Operation | Time | Allocations | Memory |
|---|---:|---:|---:|
| Verify (2-level) | 867ns | 0 | 0 B |
| VerifyMultiLevel (3-level) | 875ns | 0 | 0 B |
| VerifyAbsent (2-level) | 1.4us | 0 | 0 B |

**Takeaway:** Verification is pure hash recomputation. Zero allocations. Sub-microsecond for inclusion, ~1.4us for absence. This is the hot path for validators.

## Proof Size

How many bytes does a proof require on the wire?

| Tree | Groups | Leaves/Group | Proof Bytes | Steps |
|---|---:|---:|---:|---:|
| 2-level | 100 | 1,000 | 664 bytes | 17 |
| 3-level | 50x5 | 20 | 606 bytes | 14 |

Each step is 33 bytes (32-byte sibling hash + 1-byte direction). Proof size is O(log G + log L) steps.

**Takeaway:** Proofs are compact. Under 1KB even for large trees. Self-contained (verifiable without the original tree or any database).

## Diff Performance

How fast can you detect changes between two forests?

| Operation | Groups | Leaves | Time | Allocs |
|---|---:|---:|---:|---:|
| Diff (group-level) | 100 | 10,000 | 2.6us | 2 |
| DiffMultiLevel | 50 | 5,000 | 5.5us | 3 |
| DiffLeaves (within 1 group) | 1 | 1,000 | 42us | 18 |

**Takeaway:** Group-level diff is O(groups) root comparisons. Under 3us for 100 groups. Only drill into DiffLeaves for the specific groups that changed.

## Scoped Queries

How fast can you compute a SubRoot for a subset of groups?

| Operation | Subset Size | Total Groups | Time |
|---|---:|---:|---:|
| SubRoot (2-level) | 10 | 100 | 1.3us |
| SubgraphRoot (3-level) | 10 | 50 | 1.1us |

**Takeaway:** SubRoot is O(S log S) where S is the subset. Sub-2us for typical use (cache key computation).

## Summary

| Operation | Typical Latency | Zero-Alloc? |
|---|---:|---:|
| Build (10K leaves) | 1.2ms | No |
| Prove | 9-16us | No |
| **Verify** | **867ns** | **Yes** |
| ProveAbsent | 18us | No |
| **VerifyAbsent** | **1.4us** | **Yes** |
| **Diff (100 groups)** | **2.6us** | Nearly (2 allocs) |
| SubRoot | 1.3us | No |

The verification path (the thing validators run millions of times) is zero-allocation and sub-microsecond. Build and prove are fast enough for online use but not the hot path.
