package ntfs

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

/*
func GetFileRawSD(filename string) ([]byte, error) {
	if len(filename) == 0 {
		return nil, &os.PathError{"ReadSecurityDescriptor", filename, syscall.Errno(syscall.ERROR_PATH_NOT_FOUND)}
	}

	filenamep, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return nil, &os.PathError{"ReadSecurityDescriptor", filename, err}
	}
	out = make([]byte, sz)
	return out, err
}
*/

/*
func getSecurityInfo() (handle, objectType, securityInfo, owner, group, dacl, sacl, sd) {

}
*/
