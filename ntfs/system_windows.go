package ntfs

import (
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetFileSecurityW = modadvapi32.NewProc("GetFileSecurityW")
)

// GetFileSecurity retrieves a security descriptor for the given file or
// directory from the file system.
func GetFileSecurity(path *uint16, reqInfo uint32, buffer []byte) (length uint32, err error) {
	var _p0 *byte
	if len(buffer) > 0 {
		_p0 = &buffer[0]
	}
	_p1 := &length
	r1, _, e1 := syscall.Syscall6(procGetFileSecurityW.Addr(), 5, uintptr(unsafe.Pointer(path)), uintptr(reqInfo), uintptr(unsafe.Pointer(_p0)), uintptr(len(buffer)), uintptr(unsafe.Pointer(_p1)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

/*
func GetSecurityInfo() (handle, objectType, securityInfo, owner, group, dacl, sacl, sd) {

}
*/
