package mirrorfs

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type Node struct {
	*os.File
}

func NewNode(file *os.File) (Node, error) {
	_, err := file.Stat()
	if err != nil {
		return Node{}, fuse.ENOENT // FIXME: Correct error response?
	}
	return Node{file}, nil
}

func (n Node) IsDir() bool {
	if fi, _ := n.File.Stat(); fi.IsDir() {
		return true
	}
	return false
}

func (n Node) Kind() string {
	if n.IsDir() {
		return "DIR"
	}
	return "FILE"
}

// FS Methods

var _ fs.FS = (*Node)(nil)

func (f Node) Root() (fs.Node, error) {
	return f, nil
}

// Node Methods

var _ fs.Node = (*Node)(nil)

func (n Node) Attr(a *fuse.Attr) {
	log.Printf("%s ATTR: %s", n.Kind(), n.Name())
	attrOSToFuse(n.File, a)
}

var _ = fs.NodeForgetter(&Node{})

func (n Node) Forget() {
	log.Printf("%s FORGET: %s", n.Kind(), n.Name())
	n.Close()
}

var _ = fs.NodeGetxattrer(&Node{})

func (n Node) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) (err error) {
	log.Printf("%s GETXATTR: %s %v", n.Kind(), n.Name(), req)
	resp.Xattr, err = GetFileXAttr(n.File, req.Name, req.Size, req.Position)
	return
}

var _ = fs.NodeListxattrer(&Node{})

func (n Node) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	log.Printf("%s LISTXATTR: %s %v", n.Kind(), n.Name(), req)
	resp.Xattr, err = ListFileXAttr(n.File, req.Size, req.Position)
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

// Directory methods

var _ = fs.NodeRequestLookuper(&Node{})

func (d Node) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fs.Node, error) {
	//fi, err := file.Stat()
	path := filepath.Join(d.Name(), req.Name)
	log.Printf("%s LOOKUP: %s : %s", d.Kind(), req.Name, path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fuse.ENOENT // FIXME: Correct error response?
	}
	return NewNode(file)
}

var _ = fs.HandleReadDirAller(&Node{})

func (d Node) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.Printf("%s READDIR: %s", d.Kind(), d.Name())
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

// File methods

var _ = fs.HandleReader(&Node{})

func (f Node) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	log.Printf("FILE READ: %s %v", f.Name(), req)
	data := resp.Data[:req.Size] // Bazil allocates the data with a capacity of req.Size but initializes its length to 0
	n, err := f.File.ReadAt(data, int64(req.Offset))
	resp.Data = data[:n]
	if err == io.EOF {
		return nil
	}
	return err
}
