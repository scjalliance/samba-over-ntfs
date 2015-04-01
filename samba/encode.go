package samba

import "go.scj.io/samba-over-ntfs/ntsecurity"

const (
	XattrDescription = "ntfs"
)

const (
	xattrFixedBytes                        = 2 + 2 + 4
	securityDescriptorV4PreambleFixedBytes = 4
	securityDescriptorV4FixedBytes         = securityDescriptorV4PreambleFixedBytes + 2 + 64 + len(XattrDescription) + 8 + 64
)

func (sd *SambaSecDescXAttr) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sd.BinaryLength())
	err = sd.PutBinary(data)
	return
}

func (sd *SambaSecDescXAttr) PutBinary(data []byte) (err error) {
	// TODO: Take the version to write as a parameter? Or store the desired version in SambaSecDescXAttr?
	// Note: Version 1 is for NT-only ACLs that are *not* based on a posix ACL
	// Note: Version 2 is generally not used
	// Note: Version 3 is for NT-only ACLs that are *not* based on a posix ACL (includes hash of NT descriptor)
	// Note: Version 4 is for posix ACLs that have been translated into an NT equivalent (includes hash of NT descriptor and posix ACL)
	n := NativeXAttr(data)
	n.SetVersion(3)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return
	}
	n.SetSecurityDescriptorPresence(true)
	offset := n.SecurityDescriptorOffset()
	return (*SambaSecDescV4)(sd).PutBinary(data[offset:], offset)
}

func (sd *SambaSecDescXAttr) BinaryLength() (size uint32) {
	size = xattrFixedBytes
	if sd != nil {
		size += (*SambaSecDescV4)(sd).BinaryLength()
	}
	return
}

func (sd *SambaSecDescV4) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sd.BinaryLength())
	err = sd.PutBinary(data, 0)
	return
}

func (sd *SambaSecDescV4) PutBinary(data []byte, offset uint32) (err error) {
	n := NativeSecurityDescriptorHashV4(data)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return
	}
	n.SetSecurityDescriptorPresence(true)
	return (*ntsecurity.SecurityDescriptor)(sd).PutBinary(data[4:])
}

func (sd *SambaSecDescV4) BinaryLength() (size uint32) {
	size = securityDescriptorV4PreambleFixedBytes
	if sd != nil {
		size += (*ntsecurity.SecurityDescriptor)(sd).BinaryLength()
	}
	return
}
