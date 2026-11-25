package azuredisk

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const (
	defaultBlockSize   = 1 << 20
	defaultCacheBlocks = 32
	maxAttempts        = 3
)

// rangeSource reads a managed-disk snapshot over its read SAS with HTTP Range
// requests. Unallocated page-blob ranges come back as zeros from the service,
// which is the sparse-as-zeros contract.
type rangeSource struct {
	// ctx is the Open context: io.ReaderAt carries none of its own.
	ctx       context.Context
	client    *http.Client
	url       string
	size      int64
	blockSize int64
	backoff   time.Duration

	mu    sync.Mutex
	cap   int
	order *list.List
	items map[int64]*list.Element
}

type cacheEntry struct {
	index int64
	data  []byte
}

func newRangeSource(ctx context.Context, client *http.Client, sasURL string, size, blockSize int64, cacheBlocks int, backoff time.Duration) *rangeSource {
	return &rangeSource{
		ctx: ctx, client: client, url: sasURL, size: size, blockSize: blockSize, backoff: backoff,
		cap: cacheBlocks, order: list.New(), items: map[int64]*list.Element{},
	}
}

func (r *rangeSource) Size() int64 { return r.size }

func (r *rangeSource) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order.Init()
	r.items = map[int64]*list.Element{}
	return nil
}

// ReadAt implements io.ReaderAt.
func (r *rangeSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("azuredisk: negative offset %d", off)
	}
	if off >= r.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if remaining := r.size - off; want > remaining {
		want = remaining
	}
	var n int64
	for n < want {
		pos := off + n
		idx := pos / r.blockSize
		block, err := r.block(idx)
		if err != nil {
			return int(n), err
		}
		n += int64(copy(p[n:want], block[pos-idx*r.blockSize:]))
	}
	if int(n) < len(p) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func (r *rangeSource) block(idx int64) ([]byte, error) {
	r.mu.Lock()
	if el, ok := r.items[idx]; ok {
		r.order.MoveToFront(el)
		data := el.Value.(*cacheEntry).data
		r.mu.Unlock()
		return data, nil
	}
	r.mu.Unlock()

	data, err := r.fetch(idx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[idx]; !ok {
		r.items[idx] = r.order.PushFront(&cacheEntry{index: idx, data: data})
		for r.order.Len() > r.cap {
			oldest := r.order.Back()
			r.order.Remove(oldest)
			delete(r.items, oldest.Value.(*cacheEntry).index)
		}
	}
	return data, nil
}

func (r *rangeSource) fetch(idx int64) ([]byte, error) {
	start := idx * r.blockSize
	end := min(start+r.blockSize, r.size) - 1
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-r.ctx.Done():
				return nil, unreadable(start, end, r.ctx.Err())
			case <-time.After(r.backoff << (attempt - 1)):
			}
		}
		data, retry, err := r.fetchOnce(start, end)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, lastErr
}

// fetchOnce reports whether a failure is worth another attempt.
func (r *rangeSource) fetchOnce(start, end int64) (data []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, false, unreadable(start, end, errors.New("bad access URL"))
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := r.client.Do(req)
	if err != nil {
		// A url.Error repeats the SAS URL, whose query string is a credential.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, r.ctx.Err() == nil, unreadable(start, end, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusPartialContent:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, unreadable(start, end, fmt.Errorf("status %d", resp.StatusCode))
	default:
		// 200 means the server ignored Range and would stream the whole disk.
		return nil, false, unreadable(start, end, fmt.Errorf("status %d", resp.StatusCode))
	}
	data = make([]byte, end-start+1)
	if _, err := io.ReadFull(resp.Body, data); err != nil {
		return nil, true, unreadable(start, end, err)
	}
	return data, false, nil
}

func unreadable(start, end int64, cause error) error {
	return fmt.Errorf("azuredisk: read bytes %d-%d: %v: %w", start, end, cause, diskscan.ErrBlockUnreadable)
}
