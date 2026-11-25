package diskscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/ext4"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/xfs"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// errOverCap marks a read stopped by a Limits bound.
var errOverCap = errors.New("diskscan: read cap exceeded")

const (
	maxSymlinkHops = 40
	maxResolveStep = 4096
	maxStatusDir   = 100_000
	modeFmt        = 0xF000
	modeReg        = 0x8000
	modeDir        = 0x4000
	modeLink       = 0xA000
	dpkgStatusDir  = "var/lib/dpkg/status.d"
)

// RawFS is the inode-level view LimitedFS needs from a filesystem reader.
// Lookup and ReadLink errors that mean "absent" must wrap fs.ErrNotExist.
type RawFS interface {
	Root() uint64
	Lookup(dir uint64, name string) (uint64, error)
	Stat(ino uint64) (mode uint32, size int64, err error)
	ReadLink(ino uint64) (string, error)
	DirNames(ino uint64) ([]string, error)
	ReadAt(ino uint64, p []byte, off int64) (int, error)
}

var (
	_ RawFS = (*ext4.FS)(nil)
	_ RawFS = (*xfs.FS)(nil)
)

// notDB are allowlisted manifest paths that are not an OS package database.
var notDB = []string{
	"etc/os-release", "usr/lib/os-release", "etc/alpine-release",
	"package-lock.json", "requirements.txt",
}

// LimitedFS is an fs.FS over a disk's filesystem that exposes only what the OS
// package inventory reads: pkginventory.PackageManifestPaths(), the rpm
// database directories, the os-release files and the dpkg status.d directory.
// Its root lists nothing, so a walk finds no language manifests. Symlinks are
// resolved inside the image, never against the host.
//
// A read that fails for any reason except absence is recorded: the parsers
// treat an unopenable file as missing, so the caller must check Fault before
// trusting an inventory.
type LimitedFS struct {
	ctx      context.Context
	raw      RawFS
	allowed  map[string]bool
	maxFile  int64
	maxTotal int64

	mu        sync.Mutex
	total     int64
	fault     error
	dbRead    bool
	osRelease bool
}

// NewLimitedFS wraps raw. lim is applied with its defaults.
func NewLimitedFS(ctx context.Context, raw RawFS, lim Limits) *LimitedFS {
	lim = lim.withDefaults()
	allowed := map[string]bool{"etc/os-release": true, "usr/lib/os-release": true}
	for _, p := range pkginventory.PackageManifestPaths() {
		allowed[p] = true
	}
	return &LimitedFS{ctx: ctx, raw: raw, allowed: allowed, maxFile: lim.MaxFileBytes, maxTotal: lim.MaxTotalBytes}
}

// Fault is the first non-absence failure seen, nil when every read succeeded.
func (l *LimitedFS) Fault() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fault
}

// PackageDBRead reports whether an OS package database was opened successfully.
func (l *LimitedFS) PackageDBRead() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dbRead
}

// OSReleaseRead reports whether an os-release file was opened successfully.
func (l *LimitedFS) OSReleaseRead() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.osRelease
}

func (l *LimitedFS) record(err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fault == nil {
		l.fault = err
	}
	return err
}

func (l *LimitedFS) isAllowedFile(name string) bool {
	if l.allowed[name] {
		return true
	}
	dir, base, ok := cutLast(name)
	if !ok || base == "" {
		return false
	}
	return dir == "var/lib/rpm" || dir == "usr/lib/sysimage/rpm" || dir == dpkgStatusDir
}

func cutLast(name string) (dir, base string, ok bool) {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return "", name, false
	}
	return name[:i], name[i+1:], true
}

// Open implements fs.FS.
func (l *LimitedFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if err := l.ctx.Err(); err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: l.record(err)}
	}
	if name == "." {
		return &dirFile{info: fileInfo{name: "."}}, nil
	}
	switch {
	case name == dpkgStatusDir:
		return l.openStatusDir(name)
	case l.isAllowedFile(name):
		return l.openFile(name)
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (l *LimitedFS) fail(name string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &fs.PathError{Op: "open", Path: name, Err: l.record(err)}
}

func (l *LimitedFS) openFile(name string) (fs.File, error) {
	ino, err := l.resolve(name)
	if err != nil {
		return nil, l.fail(name, err)
	}
	mode, size, err := l.raw.Stat(ino)
	if err != nil {
		return nil, l.fail(name, err)
	}
	if mode&modeFmt != modeReg {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if size > l.maxFile {
		return nil, l.fail(name, fmt.Errorf("%s is %d bytes: %w", name, size, errOverCap))
	}
	l.mu.Lock()
	switch {
	case name == "etc/os-release" || name == "usr/lib/os-release":
		l.osRelease = true
	case !slices.Contains(notDB, name) && l.allowed[name]:
		l.dbRead = true
	}
	l.mu.Unlock()
	return &file{l: l, ino: ino, info: fileInfo{name: baseName(name), size: size}}, nil
}

func (l *LimitedFS) openStatusDir(name string) (fs.File, error) {
	ino, err := l.resolve(name)
	if err != nil {
		return nil, l.fail(name, err)
	}
	mode, _, err := l.raw.Stat(ino)
	if err != nil {
		return nil, l.fail(name, err)
	}
	if mode&modeFmt != modeDir {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	names, err := l.raw.DirNames(ino)
	if err != nil {
		return nil, l.fail(name, err)
	}
	d := &dirFile{info: fileInfo{name: baseName(name), dir: true}}
	for _, n := range names {
		child, err := l.raw.Lookup(ino, n)
		if err != nil {
			return nil, l.fail(name, err)
		}
		cm, size, err := l.raw.Stat(child)
		if err != nil {
			return nil, l.fail(name, err)
		}
		if cm&modeFmt == modeReg {
			d.entries = append(d.entries, fs.FileInfoToDirEntry(fileInfo{name: n, size: size}))
		}
	}
	l.mu.Lock()
	l.dbRead = true
	l.mu.Unlock()
	return d, nil
}

// resolve walks name from the root, following symlinks inside the image. An
// absolute target restarts at the image root and ".." never leaves it.
func (l *LimitedFS) resolve(name string) (uint64, error) {
	stack := []uint64{l.raw.Root()}
	final := stack[0]
	comps := strings.Split(name, "/")
	hops := 0
	for step := 0; len(comps) > 0; step++ {
		if step > maxResolveStep {
			return 0, fmt.Errorf("resolve %s: too many path components: %w", name, errOverCap)
		}
		if err := l.ctx.Err(); err != nil {
			return 0, err
		}
		c := comps[0]
		comps = comps[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			final = stack[len(stack)-1]
			continue
		}
		ino, err := l.raw.Lookup(stack[len(stack)-1], c)
		if err != nil {
			return 0, err
		}
		mode, _, err := l.raw.Stat(ino)
		if err != nil {
			return 0, err
		}
		switch mode & modeFmt {
		case modeLink:
			hops++
			if hops > maxSymlinkHops {
				return 0, fmt.Errorf("resolve %s: more than %d symlinks", name, maxSymlinkHops)
			}
			target, err := l.raw.ReadLink(ino)
			if err != nil {
				return 0, err
			}
			if strings.HasPrefix(target, "/") {
				stack = stack[:1]
			}
			comps = append(strings.Split(target, "/"), comps...)
		case modeDir:
			stack = append(stack, ino)
			final = ino
		default:
			if len(comps) > 0 && slices.ContainsFunc(comps, func(s string) bool { return s != "" && s != "." }) {
				return 0, fmt.Errorf("resolve %s: %w", name, fs.ErrNotExist)
			}
			final = ino
		}
	}
	return final, nil
}

func baseName(p string) string {
	_, b, ok := cutLast(p)
	if !ok {
		return p
	}
	return b
}

type fileInfo struct {
	name string
	size int64
	dir  bool
}

func (i fileInfo) Name() string { return i.name }
func (i fileInfo) Size() int64  { return i.size }
func (i fileInfo) Mode() fs.FileMode {
	if i.dir || i.name == "." {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i fileInfo) ModTime() time.Time { return time.Time{} }
func (i fileInfo) IsDir() bool        { return i.Mode().IsDir() }
func (i fileInfo) Sys() any           { return nil }

type dirFile struct {
	info    fileInfo
	entries []fs.DirEntry
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Close() error               { return nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.name, Err: errors.New("is a directory")}
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		out := d.entries
		d.entries = nil
		return out, nil
	}
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(d.entries))
	out := d.entries[:n]
	d.entries = d.entries[n:]
	return out, nil
}

type file struct {
	l    *LimitedFS
	ino  uint64
	info fileInfo
	off  int64
}

func (f *file) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *file) Close() error               { return nil }

func (f *file) Read(p []byte) (int, error) {
	if f.off >= f.info.size {
		return 0, io.EOF
	}
	if err := f.l.ctx.Err(); err != nil {
		return 0, f.l.record(err)
	}
	n := int64(len(p))
	if rest := f.info.size - f.off; n > rest {
		n = rest
	}
	f.l.mu.Lock()
	over := f.l.total+n > f.l.maxTotal
	if !over {
		f.l.total += n
	}
	f.l.mu.Unlock()
	if over {
		return 0, f.l.record(fmt.Errorf("read %s: total bytes: %w", f.info.name, errOverCap))
	}
	got, err := f.l.raw.ReadAt(f.ino, p[:n], f.off)
	f.off += int64(got)
	if err != nil && (!errors.Is(err, io.EOF) || int64(got) != n) {
		return got, f.l.record(err)
	}
	return got, nil
}
