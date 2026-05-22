package merklestrata

// DiffResult contains the groups that differ between two forests.
type DiffResult struct {
	Added     []string // groups in new but not old
	Removed   []string // groups in old but not new
	Changed   []string // groups in both but with different roots
	Truncated bool     // true if MaxChanges cap was reached
}

// DiffOptions controls diff behavior.
type DiffOptions struct {
	// Filter restricts the diff to the listed group names. When empty, all
	// groups are compared.
	Filter []string

	// MaxChanges caps the total number of changed/added/removed groups reported.
	// 0 means no cap.
	MaxChanges int
}

// Diff compares two forests and returns which groups were added, removed, or
// changed. This is O(groups), not O(leaves): it compares intermediate roots
// without examining individual leaves.
func Diff(old, new *Tree) (added, removed, changed []string) {
	r := DiffWithOptions(old, new, nil)
	return r.Added, r.Removed, r.Changed
}

// DiffWithOptions compares two forests with optional filtering and cap.
func DiffWithOptions(old, new *Tree, opts *DiffOptions) *DiffResult {
	if old == nil {
		old = &Tree{groups: map[string]*group{}}
	}
	if new == nil {
		new = &Tree{groups: map[string]*group{}}
	}

	result := &DiffResult{}

	// Build filter set.
	var filterSet map[string]bool
	if opts != nil && len(opts.Filter) > 0 {
		filterSet = make(map[string]bool, len(opts.Filter))
		for _, name := range opts.Filter {
			filterSet[name] = true
		}
	}

	maxChanges := 0
	if opts != nil {
		maxChanges = opts.MaxChanges
	}

	total := 0
	capped := func() bool {
		if maxChanges > 0 && total >= maxChanges {
			result.Truncated = true
			return true
		}
		return false
	}

	for name, ng := range new.groups {
		if filterSet != nil && !filterSet[name] {
			continue
		}
		if capped() {
			break
		}
		og, exists := old.groups[name]
		if !exists {
			result.Added = append(result.Added, name)
			total++
		} else if og.root != ng.root {
			result.Changed = append(result.Changed, name)
			total++
		}
	}

	for name := range old.groups {
		if filterSet != nil && !filterSet[name] {
			continue
		}
		if capped() {
			break
		}
		if _, exists := new.groups[name]; !exists {
			result.Removed = append(result.Removed, name)
			total++
		}
	}

	return result
}

// DiffLeaves compares the leaves of a specific group between two forests.
// Returns added and removed leaf hashes. This is useful after Diff identifies
// a changed group and you want to know which specific leaves differ.
func DiffLeaves(old, new *Tree, group string) (added, removed []Hash) {
	var oldLeaves, newLeaves []Hash
	if old != nil {
		if g, ok := old.groups[group]; ok {
			oldLeaves = g.leaves
		}
	}
	if new != nil {
		if g, ok := new.groups[group]; ok {
			newLeaves = g.leaves
		}
	}

	oldSet := make(map[Hash]struct{}, len(oldLeaves))
	for _, h := range oldLeaves {
		oldSet[h] = struct{}{}
	}
	newSet := make(map[Hash]struct{}, len(newLeaves))
	for _, h := range newLeaves {
		newSet[h] = struct{}{}
	}

	for _, h := range newLeaves {
		if _, ok := oldSet[h]; !ok {
			added = append(added, h)
		}
	}
	for _, h := range oldLeaves {
		if _, ok := newSet[h]; !ok {
			removed = append(removed, h)
		}
	}
	return added, removed
}
