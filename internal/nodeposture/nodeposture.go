// Package nodeposture is the node posture reader behind `graph node-posture`
// (ADR 094): the opt-in DaemonSet that reports the kubelet configuration and
// the stat of the CIS-listed node files, which no Kubernetes API exposes
// without nodes/proxy.
//
// The reader is deliberately dumb. It stats and reads exactly the paths it is
// given and prints one JSON document per interval to stdout; it holds no
// Kubernetes credentials and opens no connection. Vulngraph's Kubernetes collector
// reads the document back from the pod's log (pods/log in Vulngraph's own
// namespace) and does all interpretation, so the code running with host
// mounts stays small enough to audit.
package nodeposture

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Marker is the value of Document.Version; the collector ignores any log line
// that does not carry it.
const Marker = "graph-node-posture/v1"

// Kind is what the reader does with a path.
type Kind string

const (
	// KindStat reports existence, permission bits and ownership.
	KindStat Kind = "stat"
	// KindRead also reports the content (capped at MaxContent bytes).
	KindRead Kind = "read"
	// KindTree reports the directory and every regular file beneath it.
	KindTree Kind = "tree"
	// KindReadDir reports the directory and the content of each regular file
	// directly in it (kubelet --config-dir drop-ins), at most maxDirFiles.
	KindReadDir Kind = "readdir"
)

// Limits keep one document small enough for a single log line.
const (
	MaxContent = 64 << 10
	maxEntries = 512
	maxDepth   = 4
	// maxDirFiles bounds a readdir role; more files is an error, never a
	// silently shortened listing.
	maxDirFiles = 16
)

// Spec is one path the reader was told to look at, under a role name the
// collector understands (kubelet_config, pki_dir, ...).
type Spec struct {
	Role string
	Kind Kind
	Path string
}

// Document is the reader's whole output for one pass.
type Document struct {
	Version string `json:"graph_node_posture"`
	Files   []File `json:"files"`
}

// File is one role's observation. Exists=false with no Error means the path
// is absent; a non-empty Error means it could not be observed at all.
type File struct {
	Role      string  `json:"role"`
	Exists    bool    `json:"exists"`
	Error     string  `json:"error,omitempty"`
	Dir       bool    `json:"dir,omitempty"`
	Mode      string  `json:"mode,omitempty"` // permission bits, octal "0600"
	UID       *uint32 `json:"uid,omitempty"`
	GID       *uint32 `json:"gid,omitempty"`
	Content   string  `json:"content,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Entries   []Entry `json:"entries,omitempty"`
}

// Entry is a regular file found under a tree role.
type Entry struct {
	Path string `json:"path"` // relative to the role's path
	Mode string `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	// Content and Truncated are set for readdir roles only.
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ParseSpec parses "<role>=<path>" for the given kind.
func ParseSpec(kind Kind, arg string) (Spec, error) {
	role, p, ok := strings.Cut(arg, "=")
	if !ok || role == "" || p == "" {
		return Spec{}, fmt.Errorf("ParseSpec: want <role>=<path>, got %q", arg)
	}
	return Spec{Role: role, Kind: kind, Path: p}, nil
}

// Collect observes every spec. It never follows the final symlink of a stat
// target (Lstat), never writes, and never fails as a whole: each role carries
// its own error.
func Collect(specs []Spec) Document {
	doc := Document{Version: Marker, Files: make([]File, 0, len(specs))}
	for _, s := range specs {
		doc.Files = append(doc.Files, observe(s))
	}
	return doc
}

func observe(s Spec) File {
	f := File{Role: s.Role}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return f
	}
	if err != nil {
		f.Error = errorText(err)
		return f
	}
	f.Exists = true
	setStat(&f, info)
	switch s.Kind {
	case KindRead:
		content, truncated, err := readCapped(s.Path)
		if err != nil {
			f.Error = errorText(err)
			return f
		}
		f.Content, f.Truncated = content, truncated
	case KindTree:
		entries, err := walk(s.Path)
		if err != nil {
			f.Error = errorText(err)
			return f
		}
		f.Entries = entries
	case KindReadDir:
		entries, err := readDir(s.Path)
		if err != nil {
			f.Error = errorText(err)
			return f
		}
		f.Entries = entries
	}
	return f
}

// readDir reads every regular file directly in dir, in name order.
func readDir(dir string) ([]Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("readDir: %w", err)
	}
	var out []Entry
	for _, d := range des {
		if !d.Type().IsRegular() {
			continue
		}
		if len(out) == maxDirFiles {
			return nil, fmt.Errorf("readDir: %w", errTooMany)
		}
		p := filepath.Join(dir, d.Name())
		info, err := d.Info()
		if err != nil {
			return nil, fmt.Errorf("readDir: %w", err)
		}
		content, truncated, err := readCapped(p)
		if err != nil {
			return nil, fmt.Errorf("readDir: %w", err)
		}
		e := Entry{Path: d.Name(), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), Content: content, Truncated: truncated}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			e.UID, e.GID = st.Uid, st.Gid
		}
		out = append(out, e)
	}
	return out, nil
}

func setStat(f *File, info fs.FileInfo) {
	f.Dir = info.IsDir()
	f.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid := st.Uid, st.Gid
		f.UID, f.GID = &uid, &gid
	}
}

func readCapped(p string) (string, bool, error) {
	fh, err := os.Open(p)
	if err != nil {
		return "", false, fmt.Errorf("readCapped: %w", err)
	}
	defer func() { _ = fh.Close() }()
	b, err := io.ReadAll(io.LimitReader(fh, MaxContent+1))
	if err != nil {
		return "", false, fmt.Errorf("readCapped: %w", err)
	}
	if len(b) > MaxContent {
		return string(b[:MaxContent]), true, nil
	}
	return string(b), false, nil
}

// errTooMany stops a walk that would not fit in one document; a truncated
// listing would read as "every file checked".
var errTooMany = errors.New("nodeposture: too many entries")

func walk(root string) ([]Entry, error) {
	var out []Entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel != "." && strings.Count(rel, string(filepath.Separator)) >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if len(out) == maxEntries {
			return errTooMany
		}
		e := Entry{Path: rel, Mode: fmt.Sprintf("%04o", info.Mode().Perm())}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			e.UID, e.GID = st.Uid, st.Gid
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	return out, nil
}

// errorText keeps the error class without the host path, which the collector
// already knows from the role.
func errorText(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, errTooMany):
		return "too many entries"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
