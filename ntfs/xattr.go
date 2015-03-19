package ntfs

import (
	"log"

	"go.scj.io/samba-over-ntfs/ntsd"
)

// ReadFileSD will return the security descriptor for the requested file
func ReadFileSD(filename string) (*ntsd.SecurityDescriptor, error) {
	bytes, err := ReadFileRawSD(filename)
	if err != nil {
		return nil, err
	}
	sd := new(ntsd.SecurityDescriptor)
	*sd = ntsd.UnmarshalSecurityDescriptor(bytes)
	return sd, nil
}

// WriteFileSD will write the given security descriptor to the specified file
func WriteFileSD(filename string, sd *ntsd.SecurityDescriptor) error {
	// TODO: Write this function
	//return WriteFileRawSD(filename, AttributeName)
	log.Fatal("Writing to files is not yet supported")
	return nil
}
