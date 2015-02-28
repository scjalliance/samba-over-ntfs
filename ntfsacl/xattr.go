package ntfsacl

import (
	"sync"
	"syscall"
)

var aclXattrLock sync.RWMutex
var aclXattr = "system.ntfs_acl"

// SetXattr will override the default "system.ntfs_acl" for dev/test purposes
func SetXattr(xattr string) {
	aclXattrLock.Lock()
	defer aclXattrLock.Unlock()
	aclXattr = xattr
}

// Read will return the raw NTFS-stored ACL for the requested file
func Read(filename string) (out []byte, err error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	sz, err := syscall.Getxattr(filename, aclXattr, nil)
	out = make([]byte, sz)
	_, err = syscall.Getxattr(filename, aclXattr, out)
	return out, err
}
