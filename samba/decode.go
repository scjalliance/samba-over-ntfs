package samba

import "go.scj.io/samba-over-ntfs/ntsecurity"

// UnmarshalXAttr reads a security descriptor from a byte slice containing
// system.NTACL data formatted according to a Samba NDR data layout.
func UnmarshalXAttr(b []byte) ntsecurity.SecurityDescriptor {
	n := NativeXAttr(b)
	//fmt.Printf("%d %d %x %d\n", n.Version(), n.VersionNDR(), b[4:8], n.SecurityDescriptorOffset())
	if !n.Valid() || !n.ContainsSecurityDescriptor() {
		// TODO: Return an error of some kind
		return ntsecurity.SecurityDescriptor{}
	}
	switch n.Version() {
	case 4:
		return UnmarshalSecurityDescriptorHashV4(b[n.SecurityDescriptorOffset():], b)
	case 3:
		return UnmarshalSecurityDescriptorHashV3(b[n.SecurityDescriptorOffset():], b)
	case 2:
		return UnmarshalSecurityDescriptorHashV2(b[n.SecurityDescriptorOffset():], b)
	case 1:
		return UnmarshalSecurityDescriptor(b[n.SecurityDescriptorOffset():], b)
	default:
		// TODO: Return an error of some kind
		return ntsecurity.SecurityDescriptor{}
	}
}

// UnmarshalSecurityDescriptorHashV4 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 4.
func UnmarshalSecurityDescriptorHashV4(b []byte, s []byte) ntsecurity.SecurityDescriptor {
	n := NativeSecurityDescriptorHashV4(b)
	//fmt.Printf("%d %d %x %s %d %x %d %x %d\n", binary.LittleEndian.Uint32(b[0:4]), n.HashType(), n.Hash(), n.Description(), n.TimeOffset(), b[n.TimeOffset():n.TimeOffset()+8], n.SysACLHashOffset(), n.SysACLHash(), n.SecurityDescriptorOffset())
	return UnmarshalSecurityDescriptor(b[n.SecurityDescriptorOffset():], s)
}

// UnmarshalSecurityDescriptorHashV3 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 3.
func UnmarshalSecurityDescriptorHashV3(b []byte, s []byte) ntsecurity.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsecurity.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptorHashV2 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 2.
func UnmarshalSecurityDescriptorHashV2(b []byte, s []byte) ntsecurity.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsecurity.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice
// containing security descriptor data formatted according to a Samba NDR data
// layout.
func UnmarshalSecurityDescriptor(b []byte, s []byte) ntsecurity.SecurityDescriptor {
	// TODO: Write this code
	n := ntsecurity.NativeSecurityDescriptor(b)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	d := ntsecurity.SecurityDescriptor{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Owner = new(ntsecurity.SID)
		*d.Owner = ntsecurity.UnmarshalSID(s[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Group = new(ntsecurity.SID)
		*d.Group = ntsecurity.UnmarshalSID(s[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if d.Control.HasFlag(ntsecurity.SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.SACL = new(ntsecurity.ACL)
		*d.SACL = ntsecurity.UnmarshalACL(s[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	if d.Control.HasFlag(ntsecurity.DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.DACL = new(ntsecurity.ACL)
		*d.DACL = ntsecurity.UnmarshalACL(s[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	return d
}
