package samba

import "go.scj.io/samba-over-ntfs/ntsd"

// UnmarshalXAttr reads a security descriptor from a byte slice containing
// system.NTACL data formatted according to a Samba NDR data layout.
func UnmarshalXAttr(b []byte) ntsd.SecurityDescriptor {
	n := NativeXAttr(b)
	if !n.Valid() || !n.ContainsSecurityDescriptor() {
		// TODO: Return an error of some kind
		return ntsd.SecurityDescriptor{}
	}
	switch n.Version() {
	case 4:
		return UnmarshalSecurityDescriptorHashV4(b[n.SecurityDescriptorOffset():])
	case 3:
		return UnmarshalSecurityDescriptorHashV3(b[n.SecurityDescriptorOffset():])
	case 2:
		return UnmarshalSecurityDescriptorHashV2(b[n.SecurityDescriptorOffset():])
	case 1:
		return UnmarshalSecurityDescriptor(b[n.SecurityDescriptorOffset():])
	default:
		// TODO: Return an error of some kind
		return ntsd.SecurityDescriptor{}
	}
}

// UnmarshalSecurityDescriptorHashV4 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 4.
func UnmarshalSecurityDescriptorHashV4(b []byte) ntsd.SecurityDescriptor {
	n := NativeSecurityDescriptorHashV4(b)
	return UnmarshalSecurityDescriptor(b[n.SecurityDescriptorOffset():])
}

// UnmarshalSecurityDescriptorHashV3 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 4.
func UnmarshalSecurityDescriptorHashV3(b []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsd.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptorHashV2 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 4.
func UnmarshalSecurityDescriptorHashV2(b []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsd.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice
// containing security descriptor data formatted according to a Samba NDR data
// layout.
func UnmarshalSecurityDescriptor(b []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code
	n := NativeSecurityDescriptor(b)
	return ntsd.SecurityDescriptor{
		Revision: n.Revision(),
		//Alignment: n.Alignment(),
		//Control:   n.Control(),
	}
}
