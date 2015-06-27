package sambasecurity

import "log"

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file.
func ReadFileRawSD(path string) (data []byte, err error) {
	// FIXME: Retrieve the actual bytes via new syscall wrappers
	log.Fatal("Reading Samba security descriptors on Windows is not supported.")
	return
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file.
func ReadFileAttribute(path string, attr string) (data []byte, err error) {
	log.Fatal("Reading file attributes on Windows is not supported.")
	return
}

// WriteFileRawSD will write the given bytes to the specified file's security
// descriptor attribute.
func WriteFileRawSD(path string, data []byte) (err error) {
	// FIXME: Retrieve the actual bytes via new syscall wrappers
	log.Fatal("Writing Samba security descriptors on Windows is not supported.")
	return
}

// WriteFileAttribute will write binary data to the specified file within
// a particular extended attribute. Existing data will be overwritten.
func WriteFileAttribute(path string, attr string, data []byte) (err error) {
	log.Fatal("Writing file attributes on Windows is not supported.")
	return
}
