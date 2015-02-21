// Package sambaacl is intended as the Samba-side of the ACL equation.
package sambaacl

import (
	"sync"
	"syscall"
)

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

// Read will return the raw NTFS-stored ACL for the requested file
func Read(filename string) (out []byte, err error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	sz, err := syscall.Getxattr(filename, aclXattr, nil)
	out = make([]byte, sz)
	_, err = syscall.Getxattr(filename, aclXattr, out)
	return out, err
}

// Write will write to the ACL xattr for the requested file
func Write(filename string, value []byte) (err error) {
	aclXattrLock.RLock()
	defer aclXattrLock.RUnlock()
	return syscall.Setxattr(filename, aclXattr, value, xattrReplace)

	// aclXattrLock.RLock()
	// defer aclXattrLock.RUnlock()
	// cmd := exec.Command("setfattr", "-n", aclXattr, "-v", "0s"+base64.URLEncoding.EncodeToString(value), filename)
	// stdoutPipe, _ := cmd.StdoutPipe()
	// stderrPipe, _ := cmd.StderrPipe()
	// if err := cmd.Start(); err != nil {
	// 	return nil, nil, err
	// }
	// if err := cmd.Wait(); err != nil {
	// 	return nil, nil, err
	// }
	// out, _ = ioutil.ReadAll(stdoutPipe)
	// stderr, _ = ioutil.ReadAll(stderrPipe)
	// return out, stderr, err
}
