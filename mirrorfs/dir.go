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
	log.Printf("DIR ATTR: %s", d.Name())
	attrOSToFuse(d.File, a)
}

var _ = fs.NodeForgetter(&Dir{})

func (d Dir) Forget() {
	log.Printf("DIR FORGET: %s", d.Name())
	d.File.Close()
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
	var out []fuse.Dirent
	log.Printf("DIR READDIR: %s", d.Name())
	entries, err := d.Readdir(0)
	if err != nil {
		return nil, fuse.ENOENT // FIXME: Correct error response?
	}
	for _, fi := range entries {
		out = append(out, direntOSToFuse(fi))
	}
	return out, nil
}

var _ = fs.NodeGetxattrer(&Dir{})

func (d Dir) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) (err error) {
	log.Printf("DIR GETXATTR: %s : %s (size: %v, position: %v)", d.Name(), req.Name, req.Size, req.Position)
	resp.Xattr, err = getFileXAttr(d.File, req.Name, req.Size, req.Position)
	return
}

var _ = fs.NodeListxattrer(&Dir{})

func (d Dir) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	log.Printf("DIR LISTXATTR: %s (size: %v, position: %v)", d.Name(), req.Size, req.Position)
	resp.Xattr, err = listFileXAttr(d.File, req.Size, req.Position)
	return
}
