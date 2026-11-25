package ext4

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"strings"
)

// walkDir calls visit for every live entry of directory ino until it returns
// true. It reads one block at a time and scans linearly, which also covers
// htree directories: their index blocks look like a single empty entry.
func (f *FS) walkDir(ino uint64, visit func(name string, child uint64) bool) error {
	in, err := f.readInode(ino)
	if err != nil {
		return err
	}
	if !in.isDir() {
		return fmt.Errorf("ext4: inode %d is not a directory: %w", ino, fs.ErrNotExist)
	}
	if err := in.checkReadable(); err != nil {
		return err
	}
	if in.size > maxDirBytes {
		return fmt.Errorf("ext4: directory of %d bytes: %w", in.size, ErrTooLarge)
	}
	buf := make([]byte, f.blockSize)
	blocks := (in.size + f.blockSize - 1) / f.blockSize
	for lb := uint64(0); lb < blocks; lb++ {
		m, err := f.mapBlock(in, lb)
		if err != nil {
			return err
		}
		if m.kind != mapData {
			continue
		}
		if err := readFull(f.r, buf, int64(m.phys*f.blockSize)); err != nil {
			return fmt.Errorf("ext4: directory block: %w", mapEOF(err))
		}
		stop, err := f.scanBlock(buf, visit)
		if err != nil || stop {
			return err
		}
	}
	return nil
}

func (f *FS) scanBlock(buf []byte, visit func(string, uint64) bool) (bool, error) {
	le := binary.LittleEndian
	for off := 0; off < len(buf); {
		if len(buf)-off < 8 {
			return false, fmt.Errorf("ext4: directory entry tail: %w", ErrCorrupt)
		}
		child := uint64(le.Uint32(buf[off:]))
		recLen := int(le.Uint16(buf[off+4:]))
		if recLen == 0 && f.blockSize == 65536 {
			recLen = 65536
		}
		nameLen := int(buf[off+6])
		if recLen < 8 || recLen%4 != 0 || off+recLen > len(buf) || nameLen > recLen-8 {
			return false, fmt.Errorf("ext4: directory entry length %d: %w", recLen, ErrCorrupt)
		}
		if child != 0 && nameLen > 0 {
			if child > f.inodesCount {
				return false, fmt.Errorf("ext4: directory entry inode %d: %w", child, ErrCorrupt)
			}
			if visit(string(buf[off+8:off+8+nameLen]), child) {
				return true, nil
			}
		}
		off += recLen
	}
	return false, nil
}

// Lookup finds name in directory dir. A missing name, or a dir that is not a
// directory, is fs.ErrNotExist.
func (f *FS) Lookup(dir uint64, name string) (uint64, error) {
	if name == "" || strings.Contains(name, "/") {
		return 0, fs.ErrNotExist
	}
	var found uint64
	err := f.walkDir(dir, func(n string, child uint64) bool {
		if n == name {
			found = child
			return true
		}
		return false
	})
	if err != nil {
		return 0, err
	}
	if found == 0 {
		return 0, fs.ErrNotExist
	}
	return found, nil
}

// DirNames lists a directory's entries except "." and "..", bounded.
func (f *FS) DirNames(dir uint64) ([]string, error) {
	var names []string
	tooMany := false
	err := f.walkDir(dir, func(n string, _ uint64) bool {
		if n == "." || n == ".." {
			return false
		}
		if len(names) >= maxDirNames {
			tooMany = true
			return true
		}
		names = append(names, n)
		return false
	})
	if err != nil {
		return nil, err
	}
	if tooMany {
		return nil, fmt.Errorf("ext4: more than %d entries: %w", maxDirNames, ErrTooLarge)
	}
	return names, nil
}
