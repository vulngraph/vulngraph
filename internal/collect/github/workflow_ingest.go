package github

import (
	"context"
	"strings"
)

const (
	workflowConcurrency = 8
	workflowMaxFiles    = 50
)

// workflowPathsChecked reports tree/file-cap truncation separately from an
// observed empty workflow directory. Only complete reads license retirement.
func (c *Collector) workflowPathsChecked(ctx context.Context, baseURL, token string, r repo) ([]string, bool) {
	tree, ok := c.repoTree(ctx, baseURL, token, r)
	if !ok || tree.Tree == nil {
		return nil, false
	}
	complete := !tree.Truncated
	var paths []string
	for _, e := range tree.Tree {
		if e.Type != "blob" || !strings.HasPrefix(e.Path, ".github/workflows/") || strings.Contains(strings.TrimPrefix(e.Path, ".github/workflows/"), "/") {
			continue
		}
		if !strings.HasSuffix(e.Path, ".yml") && !strings.HasSuffix(e.Path, ".yaml") {
			continue
		}
		if len(paths) >= workflowMaxFiles {
			complete = false
			break
		}
		paths = append(paths, e.Path)
	}
	return paths, complete
}
