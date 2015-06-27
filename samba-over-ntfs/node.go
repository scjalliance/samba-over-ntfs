package main

import (
	"log"
	"os"
	"path/filepath"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"golang.org/x/net/context"

	"go.scj.io/samba-over-ntfs/mirrorfs"
	"go.scj.io/samba-over-ntfs/sambasecurity"
)

type Node struct {
	mirrorfs.Node
}

func NewNode(file *os.File) (Node, error) {
	n, err := mirrorfs.NewNode(file)
	return Node{n}, err
}

// FS Methods

var _ fs.FS = (*Node)(nil)

func (f Node) Root() (fs.Node, error) {
	return f, nil
}

// Node Methods

var _ = fs.NodeGetxattrer(&Node{})

func (n Node) Getxattr(ctx context.Context, req *fuse.GetxattrRequest, resp *fuse.GetxattrResponse) (err error) {
	log.Printf("%s GETXATTR: %s %v", n.Kind(), n.Name(), req)
	xattr, err := mirrorfs.GetFileXAttr(n.File, req.Name, req.Size, req.Position)
	if err == fuse.ErrNoXattr && req.Name == sambaXAttr {
		// Substitute the converted NTFS ACL if it's available
		xattr, err = mirrorfs.GetFileXAttr(n.File, ntfsXAttr, req.Size, req.Position)
		if len(xattr) > 0 && err == nil {
			if req.Size == 0 {
				// By specifying a size of 0, the caller indicates that they only want the
				// length of the xattr, not the xattr itself. This is typically used
				// by the caller to allocate an appropriately sized block of memory.
				//
				// Allocating a chunk of memory like this for the sole purpose of having its
				// length measureed later on in the API is a very poor way to communicate
				// the length of the xattr, but that's what the bazil fuse library
				// currently expects of us.
				length := len(xattr) + sambasecurity.XAttrFixedBytes // Samba v1 simply prepends a header to the NTFS format
				xattr, err = make([]byte, length), nil
			} else {
				// Convert the ACL from NTFS format to Samba format
				xattr, err = convertXAttr(xattr)
			}
		}
	}
	resp.Xattr = xattr
	return
}

var _ = fs.NodeListxattrer(&Node{})

func (n Node) Listxattr(ctx context.Context, req *fuse.ListxattrRequest, resp *fuse.ListxattrResponse) (err error) {
	log.Printf("%s NEW LISTXATTR: %s %v", n.Kind(), n.Name(), req)
	list, err := mirrorfs.ListFileXAttr(n.File, req.Size, req.Position)
	if err != nil {
		return
	}
	resp.Xattr, err = convertXAttrList(list, req.Size)
	return
}

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
