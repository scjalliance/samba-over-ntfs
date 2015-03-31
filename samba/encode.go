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
	n := NativeXAttr(data)
	n.SetVersion(4)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return nil
	}
	n.SetSecurityDescriptorPresence(true)
	return (*SambaSecDescV4)(sd).PutBinary(data[8:])
}

func (sd *SambaSecDescXAttr) BinaryLength() (size int) {
	size = xattrFixedBytes
	if sd != nil {
		size += (*SambaSecDescV4)(sd).BinaryLength()
	}
	return
}

func (sd *SambaSecDescV4) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sd.BinaryLength())
	err = sd.PutBinary(data)
	return
}

func (sd *SambaSecDescV4) PutBinary(data []byte) (err error) {
	n := NativeSecurityDescriptorHashV4(data)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return nil
	}
	n.SetSecurityDescriptorPresence(true)
	return (*ntsecurity.SecurityDescriptor)(sd).PutBinary(data[4:])
}

func (sd *SambaSecDescV4) BinaryLength() (size int) {
	size = securityDescriptorV4PreambleFixedBytes
	if sd != nil {
		size += (*ntsecurity.SecurityDescriptor)(sd).BinaryLength()
	}
	return
}
