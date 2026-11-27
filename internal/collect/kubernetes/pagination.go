package kubernetes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// listPages follows the API server's snapshot continuation until exhausted.
// A denied/expired/cancelled later page invalidates the entire enumeration.
func listPages[T any](ctx context.Context, fetch func(metav1.ListOptions) ([]T, string, string, error)) ([]T, error) {
	opts := metav1.ListOptions{Limit: 500}
	var out []T
	seen := map[string]bool{}
	objects := map[[2]string]bool{}
	var snapshot string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items, next, version, err := fetch(opts)
		if err != nil {
			return nil, fmt.Errorf("list Kubernetes page: %w", err)
		}
		if version == "" || items == nil {
			return nil, fmt.Errorf("list Kubernetes page: response omitted snapshot or items")
		}
		if snapshot != "" && snapshot != version {
			return nil, fmt.Errorf("list Kubernetes page: snapshot changed during pagination")
		}
		for i := range items {
			object, ok := any(&items[i]).(metav1.Object)
			if !ok || object.GetName() == "" {
				return nil, fmt.Errorf("list Kubernetes page: object has no identity")
			}
			id := [2]string{object.GetNamespace(), object.GetName()}
			if objects[id] {
				return nil, fmt.Errorf("list Kubernetes page: repeated object identity")
			}
			objects[id] = true
		}
		snapshot = version
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, fmt.Errorf("list Kubernetes page: repeated continuation token")
		}
		seen[next] = true
		opts.Continue = next
	}
}
