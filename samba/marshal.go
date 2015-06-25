package samba

import (
	"crypto/sha256"
	"errors"
)

const (
	XAttrDescription = "ntfs"
)

const (
	XAttrFixedBytes                = 2 + 2 + 4
	SecurityDescriptorV4FixedBytes = 4 + 2 + 64 + 1 + 8 + 64 // Does not include description, but includes description terminator
	SecurityDescriptorV3FixedBytes = 4 + 2 + 64
	SecurityDescriptorV2FixedBytes = 0
)

func (sd *SecurityDescriptor) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sd.BinaryLength())
	err = sd.PutBinary(data)
	return
}

func (sd *SecurityDescriptor) PutBinary(data []byte) (err error) {
	// TODO: Take the version to write as a parameter? Or store the desired version in SambaSecDescXAttr?
	// Note: Version 1 is for NT-only ACLs that are *not* based on a posix ACL
	// Note: Version 2 is generally not used
	// Note: Version 3 is for NT-only ACLs that are *not* based on a posix ACL (includes hash of NT descriptor)
	// Note: Version 4 is for posix ACLs that have been translated into an NT equivalent (includes hash of NT descriptor and posix ACL)
	attr := NativeXAttr(data)

	attr.SetVersion(sd.Version)
	if sd == nil {
		attr.SetSecurityDescriptorPresence(false)
		return
	}
	attr.SetSecurityDescriptorPresence(true)

	offset1 := attr.SecurityDescriptorOffset()
	offset2 := uint32(0)

	switch sd.Version {
	case 4:
		n := NativeSecurityDescriptorHashV4(data[offset1:])
		n.SetSecurityDescriptorPresence(true)
		n.SetHashType(XAttrSDHashTypeSha256)
		n.SetDescription(XAttrDescription)
		offset2 = n.SecurityDescriptorOffset()
	case 3:
		n := NativeSecurityDescriptorHashV3(data[offset1:])
		n.SetSecurityDescriptorPresence(true)
		n.SetHashType(XAttrSDHashTypeSha256)
		offset2 = n.SecurityDescriptorOffset()
	case 2:
		n := NativeSecurityDescriptorHashV2(data[offset1:])
		n.SetSecurityDescriptorPresence(true)
		offset2 = n.SecurityDescriptorOffset()
	case 1:
		n := NativeSecurityDescriptorHashV1(data[offset1:])
		offset2 = n.SecurityDescriptorOffset()
	default:
		return errors.New("Unknown Samba XAttr NTACL Version")
	}

	if err = sd.SecurityDescriptor.PutBinary(data, offset1+offset2); err != nil {
		return
	}

	switch sd.Version {
	case 4:
		n := NativeSecurityDescriptorHashV4(data[offset1:])
		hash := sha256.Sum256(data) // FIXME: Produce a V3 hash
		n.SetHash(hash[:])
	case 3:
		n := NativeSecurityDescriptorHashV3(data[offset1:])
		hash := sha256.Sum256(data)
		n.SetHash(hash[:])
	}
	return
}

func (sd *SecurityDescriptor) BinaryLength() (size uint32) {
	size = XAttrFixedBytes
	if sd != nil {
		switch sd.Version {
		case 4:
			size += uint32(SecurityDescriptorV4FixedBytes)
			size += uint32(len(XAttrDescription))
		case 3:
			size += uint32(SecurityDescriptorV3FixedBytes)
		case 2:
			size += uint32(SecurityDescriptorV2FixedBytes)
		}
		size += sd.SecurityDescriptor.BinaryLength()
	}
	return
}
