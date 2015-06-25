package main

import (
	"bytes"

	"bazil.org/fuse"
	"go.scj.io/samba-over-ntfs/ntsecurity"
	"go.scj.io/samba-over-ntfs/samba"
)

const (
	ntfsXAttr  = "system.ntfs_acl"
	sambaXAttr = "security.NTACL"
)

const (
	ntfsXAttrListEntry        = ntfsXAttr + "\x00"
	sambaXAttrListEntry       = sambaXAttr + "\x00"
	ntfsXAttrListEntryLength  = len(ntfsXAttrListEntry)
	sambaXAttrListEntryLength = len(sambaXAttrListEntry)
)

var ntfsXAttrListEntryBytes = []byte(ntfsXAttrListEntry)
var sambaXAttrListEntryBytes = []byte(sambaXAttrListEntry)

// convertFlistxattr inspects the data to determine whether an NTFS ACL is
// present, and if so returns a modified list that also includes a Samba ACL
// appended to the end.
func convertXAttrList(data []byte, size uint32) ([]byte, error) {
	// FIXME: If the order of items in the list matters reorder the elements after
	// appending the Samba ACL

	/*
		if len(data) > 0 {
			log.Printf("XAttrs list is not empty")
		} else {
			log.Printf("XAttrs list is empty")
		}
	*/
	if bytes.Contains(data, ntfsXAttrListEntryBytes) && !bytes.Contains(data, sambaXAttrListEntryBytes) {
		newLength := len(data) + sambaXAttrListEntryLength
		if newLength > int(size) {
			return nil, fuse.ERANGE
		}
		return append(data, sambaXAttrListEntry...), nil
	}
	return data, nil
}

func convertXAttr(data []byte) ([]byte, error) {
	var sd ntsecurity.SecurityDescriptor
	var xa samba.SecurityDescriptor

	err := sd.UnmarshalBinary(data)
	if err != nil {
		return nil, fuse.ErrNoXattr
	}

	xa.SecurityDescriptor = &sd
	xa.Version = 1
	output, err := xa.MarshalBinary()
	if err != nil {
		return nil, fuse.ErrNoXattr
	}
	return output, nil
}
