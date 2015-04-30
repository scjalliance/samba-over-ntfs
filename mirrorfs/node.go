package mirrorfs

import (
	"log"
	"os"

	"golang.org/x/net/context"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type Node struct {
	*os.File
}

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
	resp.Xattr, err = getFileXAttr(n.File, req.Name, req.Size, req.Position)
	return
}

var _ = fs.NodeListxattrer(&Node{})

func (n Node) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	log.Printf("%s LISTXATTR: %s %v", n.Kind(), n.Name(), req)
	resp.Xattr, err = listFileXAttr(n.File, req.Size, req.Position)
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

func (n Node) Kind() string {
	if fi, _ := n.File.Stat(); fi.IsDir() {
		return "DIR"
	}
	return "FILE"
}

func NewNode(file *os.File) (fs.Node, error) {
	fi, err := file.Stat()
	if err != nil {
		return Dir{}, fuse.ENOENT // FIXME: Correct error response?
	}
	if fi.IsDir() {
		return Dir{Node{file}}, nil
	}
	return File{Node{file}}, nil
}
