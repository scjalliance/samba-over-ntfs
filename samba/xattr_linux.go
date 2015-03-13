package samba

import "syscall"

const (
	// AttributeName is the name of the extended attribute containing Samba
	// encoded security descriptor data
	AttributeName = "security.NTACL"
	xattrReplace  = 0 // FIXME: we don't know what this value should be
)

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file
func ReadFileRawSD(filename string) ([]byte, error) {
	return ReadFileAttribute(filename, AttributeName)
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file
func ReadFileAttribute(filename string, attr string) ([]byte, error) {
	sz, err := syscall.Getxattr(filename, attr, nil)
	if err != nil {
		return nil, err
	}
	out := make([]byte, sz)
	_, err = syscall.Getxattr(filename, attr, out)
	return out, err
}

// WriteFileRawSD will write the given bytes to the specified file's security
// descriptor attribute.
func WriteFileRawSD(filename string, data []byte) error {
	return WriteFileAttribute(filename, AttributeName, data)
}

// WriteFileAttribute will write binary data to the specified file within the
// a particular extended attribute. Existing data will be overwritten
func WriteFileAttribute(path string, attr string, data []byte) error {
	return syscall.Setxattr(path, attr, data, xattrReplace)
}
