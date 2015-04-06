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
// file.
func ReadFileRawSD(path string) (data []byte, err error) {
	if len(path) == 0 {
		// FIXME: Figure out what sort of error we should really return here
		//        &os.PathError{"ReadSecurityDescriptor", filename, err}
		return nil, syscall.ERROR_FILE_NOT_FOUND
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	// FIXME: Allow the caller to specify whether they want SACLs or not. Early
	// testing suggests SACL access will always require elevated privileges.
	//reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation | ntsecurity.SACLSecurityInformation) // Everything
	reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation) // Sans SACL
	var buffer [maxSDLength]byte                                                                                                      // TODO: Factor out a function that takes a buffer as a parameter for high-throughput
	bufLen, err := ntsecurity.GetFileSecurity(pathp, reqInfo, buffer[:])
	if err != nil {
		return
	}
	data = make([]byte, bufLen)
	copy(data, buffer[:])
	return
}

// ReadFileAttribute will return the bytes in the given attribute for the requested
// file.
func ReadFileAttribute(path string, attr string) (data []byte, err error) {
	log.Fatal("Reading file attributes on Windows is not supported.")
	return nil, nil
}

// WriteFileRawSD will write the given bytes to the specified file's security
// descriptor attribute.
func WriteFileRawSD(path string, data []byte) (err error) {
	if len(path) == 0 {
		// FIXME: Figure out what sort of error we should really return here
		//        &os.PathError{"ReadSecurityDescriptor", filename, err}
		return syscall.ERROR_FILE_NOT_FOUND
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	// FIXME: Allow the caller to specify whether they want to set. Early
	// testing suggests SACL access will always require elevated privileges.
	//reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation | ntsecurity.SACLSecurityInformation) // Everything
	reqInfo := uint32(ntsecurity.OwnerSecurityInformation | ntsecurity.GroupSecurityInformation | ntsecurity.DACLSecurityInformation) // Sans SACL
	err = ntsecurity.SetFileSecurity(pathp, reqInfo, data)
	return
}

// WriteFileAttribute will write binary data to the specified file within
// a particular extended attribute. Existing data will be overwritten.
func WriteFileAttribute(path string, attr string, data []byte) (err error) {
	log.Fatal("Writing file attributes on Windows is not supported.")
	return
}
