package merkleforest

// Diff compares two forests and returns which groups were added, removed, or
// changed. This is O(groups), not O(leaves): it compares intermediate roots
// without examining individual leaves.
func Diff(old, new *Forest) (added, removed, changed []string) {
	if old == nil {
		old = &Forest{groups: map[string]*group{}}
	}
	if new == nil {
		new = &Forest{groups: map[string]*group{}}
	}

	for name, ng := range new.groups {
		og, exists := old.groups[name]
		if !exists {
			added = append(added, name)
		} else if og.root != ng.root {
			changed = append(changed, name)
		}
	}

	for name := range old.groups {
		if _, exists := new.groups[name]; !exists {
			removed = append(removed, name)
		}
	}

	return added, removed, changed
}
