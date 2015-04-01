package samba

import "go.scj.io/samba-over-ntfs/ntsecurity"

const (
	XAttrSDHashSize = 64
)

const (
	XAttrSDHashTypeNone   = 0
	XAttrSDHashTypeSha256 = 1
)

type SambaSecDescXAttr ntsecurity.SecurityDescriptor
type SambaSecDescV4 ntsecurity.SecurityDescriptor
type SambaSecDescV3 ntsecurity.SecurityDescriptor
type SambaSecDescV2 ntsecurity.SecurityDescriptor
type SambaSecDescV1 ntsecurity.SecurityDescriptor
