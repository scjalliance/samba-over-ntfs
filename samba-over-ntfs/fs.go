package main

import (
	"os"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"

	"go.scj.io/samba-over-ntfs/mirrorfs"
)

func NewFS(file *os.File) (fs.FS, error) {
	fi, err := file.Stat()
	if err != nil {
		// It no longer exists or is not accessible for some reason
		return Node{}, err // FIXME: Correct error response?
	}
	if !fi.IsDir() {
		// Not a directory
		return Node{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return Node{mirrorfs.Node{file}}, nil
}
