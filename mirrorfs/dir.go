package mirrorfs

import (
	"os"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// Dir implements both Node and Handle for directory handling
type Dir struct {
	file *os.File
}

var _ fs.Node = (*Dir)(nil)

func (d *Dir) Attr() fuse.Attr {
	if d.file == nil {
		// Root directory?
		return fuse.Attr{Mode: os.ModeDir | 0755}
	}
	if fi, err := os.Stat(d.File.Name()); err != nil {
		// TODO: Decide how to handle an error here
	}
	a.Size = fi.Size()
	a.Mode = fi.Mode()
	a.Mtime = fi.ModTime()
	a.Ctime = fi.ModTime()
	a.Crtime = fi.ModTime()
}

func (d *Dir) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fs.Node, error) {
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, err error) {

}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
  var etries []fuse.Dirent
}
