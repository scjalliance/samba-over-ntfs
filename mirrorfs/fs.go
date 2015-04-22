package mirrorfs

import (
	"os"

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
		return FS{Dir{file}}, nil
	}
	return FS{}, fuse.ENOENT // FIXME: Correct error response?
}

func NewNode(file *os.File) (fs.Node, error) {
	fi, err := file.Stat()
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return Dir{file}, nil
	}
	return File{file}, nil
}
