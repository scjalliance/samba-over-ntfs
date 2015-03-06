package ntfs

import "encoding/base64"

// GetFileRawSD will return the raw security descriptor bytes for the requested
// file
func GetFileRawSD(filename string) ([]byte, error) {
	// FIXME: Retrieve the actual bytes via new syscall wrappers
	return base64.StdEncoding.DecodeString("AQAEhIgAAACkAAAAAAAAABQAAAACAHQAAwAAAAAQJAD/AR8AAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD7wQAAAAQJAC/ARMAAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD8AQAAAAQJACpABIAAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD8QQAAAEFAAAAAAAFFQAAADf5NuUwJ3lK/OGG+8cKAAABBQAAAAAABRUAAAA3+TblMCd5SvzhhvsBAgAA")
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
