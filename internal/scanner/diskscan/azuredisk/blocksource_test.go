package azuredisk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// loopbackClient is the production safenet transport with only the loopback
// range allowed, so tests can reach httptest servers.
func loopbackClient(t *testing.T) *http.Client {
	t.Helper()
	allow, err := safenet.ParseAllowPrefixes("127.0.0.0/8")
	require.NoError(t, err)
	return safenet.NewWithTransport(5*time.Second, safenet.NewGuardedTransport(5*time.Second, allow))
}

func testImage(size int) []byte {
	img := make([]byte, size)
	for i := range img {
		img[i] = byte(i * 7)
	}
	return img
}

// rangeServer serves img with Range support. statuses, when non-empty, are
// consumed one per request before normal service starts.
type rangeServer struct {
	img      []byte
	mu       sync.Mutex
	statuses []int
	requests int
	ranges   []string
	ignore   bool
}

func (s *rangeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	s.ranges = append(s.ranges, r.Header.Get("Range"))
	var forced int
	if len(s.statuses) > 0 {
		forced, s.statuses = s.statuses[0], s.statuses[1:]
	}
	s.mu.Unlock()
	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	if s.ignore {
		_, _ = w.Write(s.img)
		return
	}
	var start, end int
	spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
	lo, hi, _ := strings.Cut(spec, "-")
	start, _ = strconv.Atoi(lo)
	end, _ = strconv.Atoi(hi)
	if start >= len(s.img) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	end = min(end, len(s.img)-1)
	w.Header().Set("Content-Range", "bytes "+lo+"-"+strconv.Itoa(end)+"/"+strconv.Itoa(len(s.img)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(s.img[start : end+1])
}

func (s *rangeServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func newSource(t *testing.T, srv *rangeServer, blockSize int64, cacheBlocks int) *rangeSource {
	t.Helper()
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return newRangeSource(context.Background(), loopbackClient(t), ts.URL+"/disk?sig=SECRET", int64(len(srv.img)), blockSize, cacheBlocks, time.Millisecond)
}

func TestRangeSource_ReadAt(t *testing.T) {
	img := testImage(1000)
	cases := []struct {
		name    string
		off     int64
		length  int
		wantN   int
		wantEOF bool
	}{
		{"within one block", 10, 20, 20, false},
		{"spans blocks", 90, 30, 30, false},
		{"whole image", 0, 1000, 1000, false},
		{"runs past the end", 990, 50, 10, true},
		{"starts at the end", 1000, 4, 0, true},
		{"starts past the end", 5000, 4, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := newSource(t, &rangeServer{img: img}, 100, 4)
			buf := make([]byte, tc.length)
			n, err := src.ReadAt(buf, tc.off)
			assert.Equal(t, tc.wantN, n)
			if tc.wantEOF {
				assert.ErrorIs(t, err, io.EOF)
			} else {
				require.NoError(t, err)
			}
			if tc.wantN > 0 {
				assert.Equal(t, img[tc.off:tc.off+int64(tc.wantN)], buf[:tc.wantN])
			}
		})
	}
}

func TestRangeSource_NegativeOffset(t *testing.T) {
	src := newSource(t, &rangeServer{img: testImage(100)}, 50, 2)
	_, err := src.ReadAt(make([]byte, 4), -1)
	require.Error(t, err)
}

func TestRangeSource_SparseZerosPassThrough(t *testing.T) {
	src := newSource(t, &rangeServer{img: make([]byte, 300)}, 100, 2)
	buf := []byte{1, 2, 3, 4}
	_, err := src.ReadAt(buf, 120)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0, 0, 0}, buf)
}

func TestRangeSource_CacheIsBoundedLRU(t *testing.T) {
	srv := &rangeServer{img: testImage(500)}
	src := newSource(t, srv, 100, 2)
	read := func(off int64) {
		_, err := src.ReadAt(make([]byte, 1), off)
		require.NoError(t, err)
	}
	read(0)   // block 0
	read(100) // block 1
	read(0)   // hit
	assert.Equal(t, 2, srv.count())
	read(200) // block 2 evicts block 1 (block 0 was just used)
	assert.Equal(t, 3, srv.count())
	read(0) // still cached
	assert.Equal(t, 3, srv.count())
	read(100) // evicted, refetched
	assert.Equal(t, 4, srv.count())
	assert.LessOrEqual(t, src.order.Len(), 2)
}

func TestRangeSource_SendsRangeHeader(t *testing.T) {
	srv := &rangeServer{img: testImage(250)}
	src := newSource(t, srv, 100, 4)
	_, err := src.ReadAt(make([]byte, 1), 220)
	require.NoError(t, err)
	assert.Equal(t, []string{"bytes=200-249"}, srv.ranges)
}

func TestRangeSource_Failures(t *testing.T) {
	cases := []struct {
		name         string
		statuses     []int
		ignoreRange  bool
		wantErr      bool
		wantRequests int
	}{
		{"403 is not retried", []int{403}, false, true, 1},
		{"404 is not retried", []int{404}, false, true, 1},
		{"416 is not retried", []int{416}, false, true, 1},
		{"200 ignoring Range is unreadable", nil, true, true, 1},
		{"503 then success", []int{503}, false, false, 2},
		{"429 twice then success", []int{429, 429}, false, false, 3},
		{"503 exhausts attempts", []int{503, 503, 503, 503}, false, true, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &rangeServer{img: testImage(100), statuses: tc.statuses, ignore: tc.ignoreRange}
			src := newSource(t, srv, 100, 2)
			_, err := src.ReadAt(make([]byte, 10), 0)
			if tc.wantErr {
				require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
				assert.NotContains(t, err.Error(), "SECRET", "the SAS must never reach an error message")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantRequests, srv.count())
		})
	}
}

func TestRangeSource_TransportErrorIsUnreadableAndRedacted(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL + "/disk?sig=SECRET"
	ts.Close()
	src := newRangeSource(context.Background(), loopbackClient(t), url, 100, 100, 1, time.Millisecond)
	_, err := src.ReadAt(make([]byte, 1), 0)
	require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
	assert.NotContains(t, err.Error(), "SECRET")
}

func TestRangeSource_CancelledContext(t *testing.T) {
	srv := &rangeServer{img: testImage(100), statuses: []int{503, 503}}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := newRangeSource(ctx, loopbackClient(t), ts.URL, 100, 100, 1, time.Hour)
	_, err := src.ReadAt(make([]byte, 1), 0)
	require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
}

func TestDefaultClientBlocksPrivateAddresses(t *testing.T) {
	ts := httptest.NewServer(&rangeServer{img: testImage(100)})
	t.Cleanup(ts.Close)
	p := New(nil, nil, Config{Access: ReadAccessFunc(func(context.Context, diskscan.Snapshot) (string, error) {
		return ts.URL, nil
	})})
	src, err := p.Open(context.Background(), diskscan.Snapshot{ID: "s", SizeBytes: 100})
	require.NoError(t, err)
	_, err = src.ReadAt(make([]byte, 1), 0)
	require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
	assert.Contains(t, err.Error(), "SSRF blocked")
}

func TestOpen(t *testing.T) {
	srv := &rangeServer{img: testImage(300)}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	access := ReadAccessFunc(func(_ context.Context, s diskscan.Snapshot) (string, error) {
		if s.ID == "denied" {
			return "", errors.New("no grant")
		}
		return ts.URL, nil
	})
	p := New(nil, nil, Config{Access: access, HTTP: loopbackClient(t), BlockSize: 100})

	src, err := p.Open(context.Background(), diskscan.Snapshot{ID: "ok", SizeBytes: 300})
	require.NoError(t, err)
	assert.Equal(t, int64(300), src.Size())
	buf := make([]byte, 3)
	_, err = src.ReadAt(buf, 150)
	require.NoError(t, err)
	assert.Equal(t, srv.img[150:153], buf)
	require.NoError(t, src.Close())

	_, err = p.Open(context.Background(), diskscan.Snapshot{ID: "denied", SizeBytes: 300})
	require.Error(t, err)
	_, err = p.Open(context.Background(), diskscan.Snapshot{ID: "nosize"})
	require.Error(t, err)
	_, err = New(nil, nil, Config{}).Open(context.Background(), diskscan.Snapshot{ID: "x", SizeBytes: 1})
	require.Error(t, err)
}
