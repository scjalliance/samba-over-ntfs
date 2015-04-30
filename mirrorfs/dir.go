package mirrorfs

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// Dir implements both Node and Handle for directory handling
type Dir struct {
	Node
}

func NewDir(file *os.File) (Dir, error) {
	fi, err := file.Stat()
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return Dir{Node{file}}, nil
	}
	return Dir{}, fuse.ENOENT // FIXME: Correct error response?
}

var _ = fs.NodeRequestLookuper(&Dir{})

func (d Dir) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fs.Node, error) {
	path := filepath.Join(d.Name(), req.Name)
	log.Printf("DIR LOOKUP: %s : %s", req.Name, path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fuse.ENOENT // FIXME: Correct error response?
	}
	return NewNode(file)
}

var _ = fs.HandleReadDirAller(&Dir{})

func (d Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.Printf("DIR READDIR: %s", d.Name())
	var out []fuse.Dirent
	// Self
	self, err := d.File.Stat()
	if err == nil {
		out = append(out, direntOSToFuse(self, "."))
	}
	// Parent
	parent, err := os.Stat(filepath.Join(d.Name(), ".."))
	if err == nil {
		out = append(out, direntOSToFuse(parent, ".."))
	}
	// Children
	// FIXME: Stream the dirents instead of slurping them
	entries, err := d.Readdir(0)
	if err != nil {
		return nil, fuse.ENOENT // FIXME: Correct error response?
	}
	for _, fi := range entries {
		out = append(out, direntOSToFuse(fi, fi.Name()))
	}
	d.Seek(0, 0) // Reset the position so that subsequent calls will start at the beginning
	return out, nil
}
