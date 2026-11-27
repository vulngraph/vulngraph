package github

import (
	"context"
	"sync"
)

const (
	repositoryCacheBytes   = 4 << 20
	repositoryCacheEntries = 64
)

// URL contains the exact base, repository, ref, path and request options. These
// two readers always use GET with the same Accept header. Authorization is part
// of the key even though a cache normally serves only one installation token.
type repositoryReadKey struct{ URL, Token string }
type repositoryCacheContextKey struct{}
type repositoryReadCache struct {
	mu      sync.Mutex
	trees   map[repositoryReadKey]treeResponse
	files   map[repositoryReadKey]string
	bytes   int
	entries int
	closed  bool
}

func withRepositoryReadCache(ctx context.Context) (context.Context, *repositoryReadCache) {
	c := &repositoryReadCache{trees: map[repositoryReadKey]treeResponse{}, files: map[repositoryReadKey]string{}}
	return context.WithValue(ctx, repositoryCacheContextKey{}, c), c
}

func repositoryCache(ctx context.Context) *repositoryReadCache {
	c, _ := ctx.Value(repositoryCacheContextKey{}).(*repositoryReadCache)
	return c
}

// Accounting includes payload/key bytes and a conservative per-entry allowance;
// entry count bounds the remaining map/slice overhead. Oversized reads remain
// usable by their caller but are not retained. No raw content reaches storage.
func (c *repositoryReadCache) admit(key repositoryReadKey, payload int) bool {
	size := payload + len(key.URL) + len(key.Token) + 128
	if c.closed || c.entries >= repositoryCacheEntries || size > repositoryCacheBytes-c.bytes {
		return false
	}
	c.bytes += size
	c.entries++
	return true
}

func cloneRepositoryTree(tree treeResponse) treeResponse {
	tree.Tree = append(tree.Tree[:0:0], tree.Tree...)
	return tree
}

func (c *repositoryReadCache) tree(key repositoryReadKey) (treeResponse, bool) {
	if c == nil {
		return treeResponse{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tree, ok := c.trees[key]
	return cloneRepositoryTree(tree), ok
}

func (c *repositoryReadCache) rememberTree(key repositoryReadKey, tree treeResponse) {
	if c == nil || tree.Tree == nil || tree.Truncated {
		return
	}
	size := 0
	for _, entry := range tree.Tree {
		size += len(entry.Path) + len(entry.Type) + 64
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.trees[key]; !exists && c.admit(key, size) {
		c.trees[key] = cloneRepositoryTree(tree)
	}
}

func (c *repositoryReadCache) file(key repositoryReadKey) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	content, ok := c.files[key]
	return content, ok
}

func (c *repositoryReadCache) rememberFile(key repositoryReadKey, content string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.files[key]; !exists && c.admit(key, len(content)) {
		c.files[key] = content
	}
}

func (c *repositoryReadCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trees, c.files = nil, nil
	c.bytes, c.entries, c.closed = 0, 0, true
}
