package mirrorfs

import (
	"io"
	"log"
	"os"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type File struct {
	Node
}

func NewFile(file *os.File) (File, error) {
	fi, err := file.Stat()
	if err != nil {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return File{Node{file}}, nil
}

var _ = fs.HandleReader(&File{})

func (f File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	log.Printf("FILE READ: %s %v", f.Name(), req)
	data := resp.Data[:req.Size] // Bazil allocates the data with a capacity of req.Size but initializes its length to 0
	n, err := f.File.ReadAt(data, int64(req.Offset))
	resp.Data = data[:n]
	if err == io.EOF {
		return nil
	}
	return err
}

/*
func (f *file) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
}

func (f *file) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
}
*/
