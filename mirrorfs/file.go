package mirrorfs

import (
	"log"
	"os"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type File struct {
	*os.File
}

var _ fs.Node = (*File)(nil)

func NewFile(file *os.File) (File, error) {
	fi, err := file.Stat()
	if err != nil {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return File{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return File{file}, nil
}

func (f File) Attr(a *fuse.Attr) {
	log.Printf("FILE ATTR: %s", f.Name())
	attrOSToFuse(f.File, a)
}

var _ = fs.NodeForgetter(&File{})

func (f File) Forget() {
	log.Printf("FILE FORGET: %s", f.Name())
	f.File.Close()
}

var _ = fs.NodeGetxattrer(&File{})

func (f File) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) (err error) {
	log.Printf("FILE GETXATTR: %s %v", f.Name(), req)
	resp.Xattr, err = getFileXAttr(f.File, req.Name, req.Size, req.Position)
	return
}

var _ = fs.NodeListxattrer(&File{})

func (f File) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	log.Printf("FILE LISTXATTR: %s %v", f.Name(), req)
	resp.Xattr, err = listFileXAttr(f.File, req.Size, req.Position)
	return
}

/*
var _ = fs.NodeSetxattrer(&File{})

func (f File) Setxattr(ctx context.Context, req *fuse.SetxattrRequest) (err error) {
	log.Printf("FILE SETXATTR: %s %v", f.Name(), req)
	return nil
}

var _ = fs.NodeRemovexattrer(&File{})

func (f File) Removexattr(ctx context.Context, req *fuse.RemovexattrRequest) (err error) {
	log.Printf("FILE REMOVEXATTR: %s %v", f.Name(), req)
	return nil
}
*/

func (f *file) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	f.File.ReadAt(resp.Data, int64(req.Offset))
}

/*
func (f *file) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
}

func (f *file) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
}
*/
