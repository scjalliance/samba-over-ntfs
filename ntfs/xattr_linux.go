package ntfs

import "syscall"

const (
	// AttributeName is the name of the extended attribute containing NTFS encoded
	// security descriptor data via the ntfs-3g file system driver
	AttributeName = "system.ntfs_acl"
)

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file
func ReadFileRawSD(filename string) ([]byte, error) {
	return ReadFileAttribute(filename, AttributeName)
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file
func ReadFileAttribute(path string, attr string) ([]byte, error) {
	sz, err := syscall.Getxattr(path, xattr, nil)
	out := make([]byte, sz)
	_, err = syscall.Getxattr(path, xattr, out)
	return out, err
}

// WriteFileRawSD will write the given bytes to the specified file's security
// descriptor attribute.
func WriteFileRawSD(path string, data []byte) error {
	return WriteFileAttribute(path, AttributeName)
}

// WriteFileAttribute will write binary data to the specified file within the
// a particular extended attribute. Existing data will be overwritten
func WriteFileAttribute(path string, attr string, data []byte) error {
	return syscall.Setxattr(path, attr, value, xattrReplace)
}
