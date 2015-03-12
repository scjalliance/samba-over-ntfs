package samba

import "log"

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file
func ReadFileRawSD(filename string) ([]byte, error) {
	// FIXME: Retrieve the actual bytes via new syscall wrappers
	log.Fatal("Reading security descriptors on Windows is not yet supported.")
	return nil, nil
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file
func ReadFileAttribute(path string, attr string) ([]byte, error) {
	log.Fatal("Reading file attributes on Windows is not supported.")
	return nil, nil
}
