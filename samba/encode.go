package samba

import "go.scj.io/samba-over-ntfs/ntsecurity"

func MarshalXAttr(sd *ntsecurity.SecurityDescriptor, b []byte) {
	// TODO: Take the version to write as a parameter?
	n := NativeXAttr(b)
	n.SetVersion(4)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return
	}
	n.SetSecurityDescriptorPresence(true)
	MarshalSecurityDescriptorV4(sd, b[8:])
}

func MarshalSecurityDescriptorV4(sd *ntsecurity.SecurityDescriptor, b []byte) {
	n := NativeSecurityDescriptorHashV4(b)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return
	}
	n.SetSecurityDescriptorPresence(true)
	ntsecurity.MarshalSecurityDescriptor(sd, b)
}

const (
	XattrDescription = "ntfs"
)

const (
	xattrFixedBytes                        = 2 + 2 + 4
	securityDescriptorV4PreambleFixedBytes = 4
	securityDescriptorV4FixedBytes         = securityDescriptorV4PreambleFixedBytes + 2 + 64 + len(XattrDescription) + 8 + 64
)

func MarshalXattrBytes(sd *ntsecurity.SecurityDescriptor) int {
	if sd == nil {
		return xattrFixedBytes
	}
	return xattrFixedBytes + MarshalSecurityDescriptorV4Bytes(sd)
}

func MarshalSecurityDescriptorV4Bytes(sd *ntsecurity.SecurityDescriptor) int {
	if sd == nil {
		return securityDescriptorV4PreambleFixedBytes
	}
	return securityDescriptorV4FixedBytes + ntsecurity.MarshalSecurityDescriptorBytes(sd)
}
