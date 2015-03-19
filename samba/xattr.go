// Package samba is intended as the Samba-side of the ACL equation.
package samba

import (
	"log"

	"go.scj.io/samba-over-ntfs/ntsd"
)

// ReadFileSD will return the security descriptor for the requested file
func ReadFileSD(path string) (*ntsd.SecurityDescriptor, error) {
	bytes, err := ReadFileRawSD(path)
	if err != nil {
		return nil, err
	}
	sd := new(ntsd.SecurityDescriptor)
	*sd = UnmarshalXAttr(bytes)
	return sd, nil
}

// WriteFileSD will write the given security descriptor to the specified file
func WriteFileSD(path string, sd *ntsd.SecurityDescriptor) error {
	// TODO: Write this function
	//return WriteFileRawSD(path, AttributeName)
	log.Fatal("Writing to files is not yet supported")
	return nil
}
