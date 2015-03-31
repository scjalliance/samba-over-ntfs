package ntfs

import (
	"log"

	"go.scj.io/samba-over-ntfs/ntsecurity"
)

// ReadFileSD will return the security descriptor for the requested file
func ReadFileSD(path string) (sd *ntsecurity.SecurityDescriptor, err error) {
	bytes, err := ReadFileRawSD(path)
	if err != nil {
		return nil, err
	}
	err = sd.UnmarshalBinary(bytes)
	return sd, nil
}

// WriteFileSD will write the given security descriptor to the specified file
func WriteFileSD(path string, sd *ntsecurity.SecurityDescriptor) error {
	// TODO: Write this function
	//return WriteFileRawSD(path, AttributeName)
	log.Fatal("Writing to files is not yet supported")
	return nil
}
