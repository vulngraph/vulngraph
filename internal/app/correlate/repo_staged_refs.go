package correlate

// Each group already stores references in source order. Merge the groups with
// one cursor per group instead of copying and sorting every matching reference.
type stagedCursor struct {
	refs []stagedInputRef
	next int
}

type stagedRefQueue []stagedCursor

func (q stagedRefQueue) less(i, j int) bool {
	return q[i].refs[q[i].next].offset < q[j].refs[q[j].next].offset
}

func (q stagedRefQueue) down(root int) {
	for child := 2*root + 1; child < len(q); child = 2*root + 1 {
		if right := child + 1; right < len(q) && q.less(right, child) {
			child = right
		}
		if !q.less(child, root) {
			return
		}
		q[root], q[child] = q[child], q[root]
		root = child
	}
}

func (q *stagedRefQueue) pop() stagedInputRef {
	ref := (*q)[0].refs[(*q)[0].next]
	(*q)[0].next++
	if (*q)[0].next == len((*q)[0].refs) {
		(*q)[0] = (*q)[len(*q)-1]
		*q = (*q)[:len(*q)-1]
	}
	q.down(0)
	return ref
}

func (s *stagedFile) refsFor(types []string, account *string) stagedRefQueue {
	groups := 0
	for _, kind := range types {
		for scope, refs := range s.groups[kind] {
			if len(refs) > 0 && (account == nil || scope == *account) {
				groups++
			}
		}
	}
	queue := make(stagedRefQueue, 0, groups)
	for _, kind := range types {
		for scope, refs := range s.groups[kind] {
			if len(refs) > 0 && (account == nil || scope == *account) {
				queue = append(queue, stagedCursor{refs: refs})
			}
		}
	}
	for i := len(queue)/2 - 1; i >= 0; i-- {
		queue.down(i)
	}
	return queue
}
