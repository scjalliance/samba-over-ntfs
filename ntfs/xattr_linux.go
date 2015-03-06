package ntfs

import "syscall"

// GetFileRawSD will return the raw security descriptor bytes for the requested
// file
func GetFileRawSD(filename string) ([]byte, error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	sz, err := syscall.Getxattr(filename, aclXattr, nil)
	out := make([]byte, sz)
	_, err = syscall.Getxattr(filename, aclXattr, out)
	return out, err
}
