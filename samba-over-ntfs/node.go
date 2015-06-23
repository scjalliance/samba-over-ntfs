package main

import (
	"log"
	"os"
	"path/filepath"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"golang.org/x/net/context"

	"go.scj.io/samba-over-ntfs/mirrorfs"
)

const (
	ntfsXAttr  = "system.ntfs_acl"
	sambaXAttr = "security.NTACL"
)

type Node struct {
	mirrorfs.Node
}

func NewNode(file *os.File) (Node, error) {
	n, err := mirrorfs.NewNode(file)
	return Node{n}, err
}

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

var _ = fs.NodeGetxattrer(&Node{})

func (n Node) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) (err error) {
	if req.Name == sambaXAttr {
		//log.Printf("%s GETXATTR: %s %v", n.Kind(), n.Name(), req)

		mirrorfs.GetFileXAttr(n.File, ntfsXAttr, req.Size, req.Position)
	}

	resp.Xattr, err = mirrorfs.GetFileXAttr(n.File, req.Name, req.Size, req.Position)
	return
}

var _ = fs.NodeListxattrer(&Node{})

func (n Node) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	return n.Node.Listxattr(ctx, req, resp)
	/*
		log.Printf("%s LISTXATTR: %s %v", n.Kind(), n.Name(), req)
		resp.Xattr, err = listFileXAttr(n.File, req.Size, req.Position)
		return
	*/
}
