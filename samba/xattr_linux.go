package samba

import "syscall"

// Read will return the raw NTFS-stored ACL for the requested file
func Read(filename string) (out []byte, err error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	sz, err := syscall.Getxattr(filename, aclXattr, nil)
	out = make([]byte, sz)
	_, err = syscall.Getxattr(filename, aclXattr, out)
	return out, err
}

// Write will write to the ACL xattr for the requested file
func Write(filename string, value []byte) (err error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	return syscall.Setxattr(filename, aclXattr, value, xattrReplace)
}
