// Package sambaacl is intended as the Samba-side of the ACL equation.
package samba

import "sync"

var aclXattrLock sync.RWMutex
var aclXattr = "security.NTACL"

const (
	xattrReplace int = iota
	xattrCreate
)

// SetXattr will override the default "security.NTACL" for dev/test purposes
func SetXattr(xattr string) {
	aclXattrLock.Lock()
	defer aclXattrLock.Unlock()
	aclXattr = xattr
}
