package merkleforest_test

import (
	"crypto/sha256"
	"fmt"

	forest "github.com/blackwell-systems/merkle-forest"
)

func hash(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func ExampleBuild() {
	f := forest.Build(map[string][][32]byte{
		"users":   {hash("user.Create"), hash("user.Delete")},
		"billing": {hash("billing.Charge"), hash("billing.Refund")},
	})
	fmt.Printf("non-zero root: %v\n", f.Root != [32]byte{})
	fmt.Printf("groups: %v\n", f.Groups())
	// Output:
	// non-zero root: true
	// groups: [billing users]
}

func ExampleForest_Prove() {
	f := forest.Build(map[string][][32]byte{
		"auth": {hash("auth.Login"), hash("auth.Logout"), hash("auth.Refresh")},
	})

	proof, err := f.Prove("auth", hash("auth.Login"))
	if err != nil {
		panic(err)
	}

	valid := forest.Verify(proof, f.Root)
	fmt.Printf("valid: %v\n", valid)
	// Output:
	// valid: true
}

func ExampleForest_ProveAbsent() {
	f := forest.Build(map[string][][32]byte{
		"auth": {hash("auth.Login"), hash("auth.Logout")},
	})

	absent, err := f.ProveAbsent("auth", hash("auth.Revoke"))
	if err != nil {
		panic(err)
	}

	valid := forest.VerifyAbsent(absent, f.Root)
	fmt.Printf("absent verified: %v\n", valid)
	// Output:
	// absent verified: true
}

func ExampleForest_SubRoot() {
	f := forest.Build(map[string][][32]byte{
		"users":   {hash("user.Create")},
		"billing": {hash("billing.Charge")},
		"auth":    {hash("auth.Login")},
	})

	// Cache key for just users + auth (ignores billing changes).
	sub := f.SubRoot([]string{"users", "auth"})
	fmt.Printf("sub root (non-zero): %v\n", sub != [32]byte{})
	// Output:
	// sub root (non-zero): true
}

func ExampleDiff() {
	old := forest.Build(map[string][][32]byte{
		"users": {hash("user.Create")},
		"auth":  {hash("auth.Login")},
	})
	new := forest.Build(map[string][][32]byte{
		"users": {hash("user.Create")},           // unchanged
		"auth":  {hash("auth.Login"), hash("auth.MFA")}, // changed
		"logs":  {hash("log.Write")},             // added
	})

	added, removed, changed := forest.Diff(old, new)
	fmt.Printf("added: %v\n", added)
	fmt.Printf("removed: %v\n", removed)
	fmt.Printf("changed: %v\n", changed)
	// Output:
	// added: [logs]
	// removed: []
	// changed: [auth]
}

func ExampleBuildMultiLevel() {
	ml := forest.BuildMultiLevel([]forest.MultiLevelInput{
		{Leaf: hash("e1"), Group: "pkg/auth", Subgroup: "calls"},
		{Leaf: hash("e2"), Group: "pkg/auth", Subgroup: "imports"},
		{Leaf: hash("e3"), Group: "pkg/store", Subgroup: "calls"},
	})

	proof, err := ml.Prove("pkg/auth", "calls", hash("e1"))
	if err != nil {
		panic(err)
	}

	valid := forest.VerifyMultiLevel(proof, ml.Root)
	fmt.Printf("3-level proof valid: %v\n", valid)
	fmt.Printf("groups: %d, leaves: %d\n", len(ml.GroupRoots), ml.TotalLeaves)
	// Output:
	// 3-level proof valid: true
	// groups: 2, leaves: 3
}
