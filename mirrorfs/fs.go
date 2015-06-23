package mirrorfs

import (
	"os"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
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
	return Node{file}, nil
}
