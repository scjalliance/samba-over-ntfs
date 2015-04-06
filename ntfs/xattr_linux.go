package ntfs

import "syscall"

const (
	// AttributeName is the name of the extended attribute containing NTFS encoded
	// security descriptor data via the ntfs-3g file system driver
	AttributeName = "system.ntfs_acl"
	xattrReplace  = 0 // FIXME: we don't know what this value should be
)

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file
func ReadFileRawSD(path string) ([]byte, error) {
	return ReadFileAttribute(path, AttributeName)
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file
func ReadFileAttribute(path string, attr string) ([]byte, error) {
	sz, err := syscall.Getxattr(path, attr, nil)
	if err != nil {
		return nil, err
	}
	out := make([]byte, sz)
	_, err = syscall.Getxattr(path, attr, out)
	return out, err
}

// WriteFileRawSD will write the given bytes to the specified file's security
// descriptor attribute.
func WriteFileRawSD(path string, data []byte) error {
	return WriteFileAttribute(path, AttributeName, data)
}

// WriteFileAttribute will write binary data to the specified file within
// a particular extended attribute. Existing data will be overwritten
func WriteFileAttribute(path string, attr string, data []byte) error {
	return syscall.Setxattr(path, attr, data, xattrReplace)
}
