package mirrorfs

import (
	"os"

	"bazil.org/fuse/fs"
)

type FS struct {
	file *os.File
}

var _ fs.FS = (*FS)(nil)

func (f *FS) Root() (fs.Node, fuse.Error) {
	n := &File{
		file: f.file,
	}
	return n, nil
}
