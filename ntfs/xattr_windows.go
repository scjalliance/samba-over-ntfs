package ntfs

import (
	"log"
	"syscall"

	"go.scj.io/samba-over-ntfs/ntsecurity"
)

const (
	maxSDLength = 65536 // Totally a guess; used for buffer allocation; needs to be aligned!
)

// ReadFileRawSD will return the raw security descriptor bytes for the requested
// file
func ReadFileRawSD(path string) ([]byte, error) {
	if len(path) == 0 {
		// FIXME: Figure out what sort of error we should really return here
		//        &os.PathError{"ReadSecurityDescriptor", filename, err}
		return nil, syscall.ERROR_FILE_NOT_FOUND
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// FIXME: Allow the caller to specify whether they want SACLs or not. Early
	// testing suggests SACL access will always require elevated privileges.
	//reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation | ntsecurity.SACLSecurityInformation) // Everything
	reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation) // Sans SACL
	var buffer [maxSDLength]byte                                                                                                      // TODO: Factor out a function that takes a buffer as a parameter for high-throughput
	bufLen, err := GetFileSecurity(pathp, reqInfo, buffer[:])
	if err != nil {
		return nil, err
	}
	data := make([]byte, bufLen)
	copy(data, buffer[:])
	return data, nil
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file
func ReadFileAttribute(path string, attr string) ([]byte, error) {
	log.Fatal("Reading file attributes on Windows is not supported.")
	return nil, nil
}
