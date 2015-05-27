package main

import (
	"os"

	"go.scj.io/samba-over-ntfs/mirrorfs"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type FS struct {
	Dir
}

var _ fs.FS = (*FS)(nil)

func (f FS) Root() (fs.Node, error) {
	return f, nil
}

func NewFS(file *os.File) (FS, error) {
	fi, err := file.Stat()
	if err != nil {
		return FS{}, err // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return FS{Dir{mirrorfs.Dir{mirrorfs.Node{file}}}}, nil
	}
	return FS{}, fuse.ENOENT // FIXME: Correct error response?
}
