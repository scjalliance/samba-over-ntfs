package main

import (
	"os"

	"bazil.org/fuse"
	"go.scj.io/samba-over-ntfs/mirrorfs"
)

type Dir struct {
	mirrorfs.Dir
}

func NewDir(file *os.File) (Dir, error) {
	fi, err := file.Stat()
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return Dir{mirrorfs.Dir{mirrorfs.Node{file}}}, nil
	}
	return Dir{}, fuse.ENOENT // FIXME: Correct error response?
}
