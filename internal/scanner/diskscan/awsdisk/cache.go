package awsdisk

import (
	"container/list"
	"sync"
)

// blockCache is a fixed-capacity LRU of verified block contents.
type blockCache struct {
	mu    sync.Mutex
	cap   int
	order *list.List
	items map[int32]*list.Element
}

type cacheEntry struct {
	index int32
	data  []byte
}

func newBlockCache(capacity int) *blockCache {
	return &blockCache{cap: capacity, order: list.New(), items: make(map[int32]*list.Element)}
}

func (c *blockCache) get(index int32) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[index]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*cacheEntry).data, true
}

func (c *blockCache) put(index int32, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[index]; ok {
		c.order.MoveToFront(el)
		el.Value.(*cacheEntry).data = data
		return
	}
	c.items[index] = c.order.PushFront(&cacheEntry{index: index, data: data})
	for c.order.Len() > c.cap {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*cacheEntry).index)
	}
}

func (c *blockCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.items = make(map[int32]*list.Element)
}

func (c *blockCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
