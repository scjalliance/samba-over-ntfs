package mirrorfs

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// Dir implements both Node and Handle for directory handling
type Dir struct {
	*os.File
}

var _ fs.Node = (*Dir)(nil)

func NewDir(file *os.File) (Dir, error) {
	fi, err := file.Stat()
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return Dir{file}, nil
	}
	return Dir{}, fuse.ENOENT // FIXME: Correct error response?
}

func (d Dir) Attr(a *fuse.Attr) {
	fmt.Printf("DIR ATTR: %s", d.Name())
	attrOSToFuse(d.File, a)
}

func (d Dir) Forget() {
	fmt.Printf("DIR FORGET: %s", d.Name())
	d.File.Close()
}

func (d Dir) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fs.Node, error) {
	path := filepath.Join(d.Name(), req.Name)
	fmt.Printf("DIR LOOKUP: %s : %s", req.Name, path)
	file, err := os.Open(path)
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return NewNode(file)
}

func (d Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	var out []fuse.Dirent
	fmt.Printf("DIR READDIR: %s", d.Name())
	entries, err := d.Readdir(0)
	if err != nil {
		return out, fuse.ENOENT // FIXME: Correct error response?
	}
	for _, fi := range entries {
		out = append(out, direntOSToFuse(fi))
	}
	return out, nil
}
