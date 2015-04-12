package mirrorfs

import (
	"os"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type File struct {
	*os.File
}

var _ fs.Node = (*File)(nil)

func (f *File) Attr(a *fuse.Attr) {
	if fi, err := os.Stat(f.File.Name()); err != nil {
		// TODO: Decide how to handle an error here
	}
	a.Size = fi.Size()
	a.Mode = fi.Mode()
	a.Mtime = fi.ModTime()
	a.Ctime = fi.ModTime()
	a.Crtime = fi.ModTime()
}

var _ = fs.NodeOpener(&File{})

func (f *File) Open(req *fuse.OpenRequest, resp *fuse.OpenResponse, intr fs.Intr) (fs.Handle, fuse.Error) {
	r, err := f.File.Open()
	if err != nil {
		return nil, err
	}
	// individual entries inside a zip file are not seekable
	resp.Flags |= fuse.OpenNonSeekable
	return f, nil
}

func (f *file) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	f.File.ReadAt(resp.Data, int64(req.Offset))
}

func (f *file) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
}

func (f *file) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
}
