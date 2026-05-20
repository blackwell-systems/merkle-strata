package merkleforest

import (
	"testing"
)

func TestProve_SingleLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("leaf1")},
	})

	proof, err := f.Prove("pkg", h("leaf1"))
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if !Verify(proof, f.Root) {
		t.Fatal("proof should verify")
	}
}

func TestProve_MultipleLeaves(t *testing.T) {
	f := Build(map[string][]Hash{
		"auth":  {h("login"), h("logout"), h("refresh")},
		"users": {h("create"), h("delete"), h("update")},
	})

	for _, leaf := range []Hash{h("login"), h("logout"), h("refresh")} {
		proof, err := f.Prove("auth", leaf)
		if err != nil {
			t.Fatalf("Prove(auth, %x): %v", leaf[:4], err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("proof for %x should verify", leaf[:4])
		}
	}

	for _, leaf := range []Hash{h("create"), h("delete"), h("update")} {
		proof, err := f.Prove("users", leaf)
		if err != nil {
			t.Fatalf("Prove(users, %x): %v", leaf[:4], err)
		}
		if !Verify(proof, f.Root) {
			t.Fatalf("proof for %x should verify", leaf[:4])
		}
	}
}

func TestProve_GroupNotFound(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a")},
	})
	_, err := f.Prove("nonexistent", h("a"))
	if err == nil {
		t.Fatal("expected error for missing group")
	}
}

func TestProve_LeafNotFound(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})
	_, err := f.Prove("pkg", h("missing"))
	if err == nil {
		t.Fatal("expected error for missing leaf")
	}
}

func TestVerify_TamperedLeaf(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b"), h("c")},
	})
	proof, _ := f.Prove("pkg", h("a"))
	proof.Leaf = h("tampered")
	if Verify(proof, f.Root) {
		t.Fatal("tampered proof should not verify")
	}
}

func TestVerify_WrongRoot(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})
	proof, _ := f.Prove("pkg", h("a"))
	if Verify(proof, h("wrong-root")) {
		t.Fatal("proof against wrong root should not verify")
	}
}

func TestVerify_Nil(t *testing.T) {
	if Verify(nil, Hash{}) {
		t.Fatal("nil proof should not verify")
	}
}

func TestProveAbsent_LeafMissing(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("c"), h("e")},
	})

	// "b" is between "a" and "c" (depends on hash ordering, but test the mechanism).
	absent, err := f.ProveAbsent("pkg", h("missing"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyAbsent(absent, f.Root) {
		t.Fatal("absence proof should verify")
	}
}

func TestProveAbsent_GroupMissing(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a")},
	})

	absent, err := f.ProveAbsent("nonexistent", h("anything"))
	if err != nil {
		t.Fatalf("ProveAbsent: %v", err)
	}
	if !VerifyAbsent(absent, f.Root) {
		t.Fatal("absence proof for missing group should verify")
	}
}

func TestProveAbsent_LeafExists(t *testing.T) {
	f := Build(map[string][]Hash{
		"pkg": {h("a"), h("b")},
	})

	_, err := f.ProveAbsent("pkg", h("a"))
	if err == nil {
		t.Fatal("expected error when proving absence of existing leaf")
	}
}

func TestVerifyAbsent_Nil(t *testing.T) {
	if VerifyAbsent(nil, Hash{}) {
		t.Fatal("nil absence proof should not verify")
	}
}

func TestProve_ManyGroups(t *testing.T) {
	groups := map[string][]Hash{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		groups[name] = []Hash{h(name + "1"), h(name + "2"), h(name + "3")}
	}
	f := Build(groups)

	for name, leaves := range groups {
		for _, leaf := range leaves {
			proof, err := f.Prove(name, leaf)
			if err != nil {
				t.Fatalf("Prove(%s, %x): %v", name, leaf[:4], err)
			}
			if !Verify(proof, f.Root) {
				t.Fatalf("proof for %s/%x should verify", name, leaf[:4])
			}
		}
	}
}
