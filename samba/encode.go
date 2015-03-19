package samba

import "go.scj.io/samba-over-ntfs/ntsd"

func MarshalXAttr(sd *ntsd.SecurityDescriptor, b []byte) {
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

func MarshalSecurityDescriptorV4(sd *ntsd.SecurityDescriptor, b []byte) {
	n := NativeSecurityDescriptorHashV4(b)
	if sd == nil {
		n.SetSecurityDescriptorPresence(false)
		return
	}
	n.SetSecurityDescriptorPresence(true)
	MarshalSecurityDescriptor(sd, b)
}

func MarshalSecurityDescriptor(sd *ntsd.SecurityDescriptor, b []byte) {
	// TODO: Write this
}

const (
	XattrDescription = "ntfs"
)

const (
	xattrFixedBytes                        = 2 + 2 + 4
	securityDescriptorV4PreambleFixedBytes = 4
	securityDescriptorV4FixedBytes         = securityDescriptorV4PreambleFixedBytes + 2 + 64 + len(XattrDescription) + 8 + 64
)

func MarshalXattrBytes(sd *ntsd.SecurityDescriptor) int {
	if sd == nil {
		return xattrFixedBytes
	}
	return xattrFixedBytes + MarshalSecurityDescriptorV4Bytes(sd)
}

func MarshalSecurityDescriptorV4Bytes(sd *ntsd.SecurityDescriptor) int {
	if sd == nil {
		return securityDescriptorV4PreambleFixedBytes
	}
	return securityDescriptorV4FixedBytes + ntsd.MarshalSecurityDescriptorBytes(sd)
}
