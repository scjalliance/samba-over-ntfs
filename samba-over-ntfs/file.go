package main

import (
	"os"

	"go.scj.io/samba-over-ntfs/mirrorfs"

	"bazil.org/fuse"
)

type File struct {
	mirrorfs.File
}

func NewFile(file *os.File) (File, error) {
	fi, err := file.Stat()
	if err != nil {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return File{mirrorfs.File{mirrorfs.Node{file}}}, nil
}
