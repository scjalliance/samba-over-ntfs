package ntfsacl

import "sync"

var aclXattrLock sync.RWMutex
var aclXattr = "system.ntfs_acl"

// SetFileSDAttrName will override the default "system.ntfs_acl" for dev/test purposes
func SetFileSDAttrName(xattr string) {
	aclXattrLock.Lock()
	defer aclXattrLock.Unlock()
	aclXattr = xattr
}

// GetFileSD will return the security descriptor for the requested file
func GetFileSD(filename string) (*SecurityDescriptor, error) {
	bytes, err := GetFileRawSD(filename)
	if err != nil {
		return nil, err
	}
	sd := NtfsDecodeSecurityDescriptor(bytes)
	return sd, nil
}
