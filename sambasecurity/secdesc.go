package sambasecurity

import "go.scj.io/samba-over-ntfs/ntsecurity"

const (
	XAttrSDHashSize = 64
)

const (
	XAttrSDHashTypeNone   = 0
	XAttrSDHashTypeSha256 = 1
)

type SambaSecDescHeader struct {
	Version uint16
}

type SecurityDescriptor struct {
	Version uint16
	*ntsecurity.SecurityDescriptor
}

type SambaSecDescV4 struct {
	SambaSecDescV3
	Description string
	Time        uint64
	SysACLHash  [XAttrSDHashSize]uint8
}

type SambaSecDescV3 struct {
	SambaSecDescV1
	HashType uint16
	Hash     [XAttrSDHashSize]uint8
}

type SambaSecDescV2 struct {
	SambaSecDescV1
	Hash [16]uint8
}

type SambaSecDescV1 ntsecurity.SecurityDescriptor
