package acl

import "os/exec"

// GetFAttr will return the requested extended attribute for the requested file
func GetFAttr(attribute, filename string) (out []byte, err error) {
	out, err = exec.Command("getfattr", "--only-values", "-n", attribute, filename).Output()
	return out, err
}
