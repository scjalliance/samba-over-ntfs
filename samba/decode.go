package samba

import "go.scj.io/samba-over-ntfs/ntsd"

// UnmarshalXAttr reads a security descriptor from a byte slice containing
// system.NTACL data formatted according to a Samba NDR data layout.
func UnmarshalXAttr(b []byte) ntsd.SecurityDescriptor {
	n := NativeXAttr(b)
	//fmt.Printf("%d %d %x %d\n", n.Version(), n.VersionNDR(), b[4:8], n.SecurityDescriptorOffset())
	if !n.Valid() || !n.ContainsSecurityDescriptor() {
		// TODO: Return an error of some kind
		return ntsd.SecurityDescriptor{}
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
		return ntsd.SecurityDescriptor{}
	}
}

// UnmarshalSecurityDescriptorHashV4 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 4.
func UnmarshalSecurityDescriptorHashV4(b []byte, s []byte) ntsd.SecurityDescriptor {
	n := NativeSecurityDescriptorHashV4(b)
	//fmt.Printf("%d %d %x %s %d %x %d %x %d\n", binary.LittleEndian.Uint32(b[0:4]), n.HashType(), n.Hash(), n.Description(), n.TimeOffset(), b[n.TimeOffset():n.TimeOffset()+8], n.SysACLHashOffset(), n.SysACLHash(), n.SecurityDescriptorOffset())
	return UnmarshalSecurityDescriptor(b[n.SecurityDescriptorOffset():], s)
}

// UnmarshalSecurityDescriptorHashV3 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 3.
func UnmarshalSecurityDescriptorHashV3(b []byte, s []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsd.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptorHashV2 reads a security descriptor from a byte
// slice containing security descriptor and hash data formatted according to a
// Samba NDR data layout version 2.
func UnmarshalSecurityDescriptorHashV2(b []byte, s []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code or drop support
	return ntsd.SecurityDescriptor{}
}

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice
// containing security descriptor data formatted according to a Samba NDR data
// layout.
func UnmarshalSecurityDescriptor(b []byte, s []byte) ntsd.SecurityDescriptor {
	// TODO: Write this code
	n := NativeSecurityDescriptor(b)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	d := ntsd.SecurityDescriptor{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Owner = new(ntsd.SID)
		*d.Owner = UnmarshalSID(s[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Group = new(ntsd.SID)
		*d.Group = UnmarshalSID(s[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if d.Control.HasFlag(ntsd.SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.SACL = new(ntsd.ACL)
		*d.SACL = UnmarshalACL(s[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	if d.Control.HasFlag(ntsd.DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.DACL = new(ntsd.ACL)
		*d.DACL = UnmarshalACL(s[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	return d
}

// UnmarshalACL reads an access control list from a byte slice containing
// access control list data formatted according to a Samba NDR data layout.
func UnmarshalACL(b []byte) ntsd.ACL {
	n := NativeACL(b)
	acl := ntsd.ACL{
		Revision:   n.Revision(),
		Alignment1: n.Alignment1(),
		Alignment2: n.Alignment2(),
	}
	count := n.Count()
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the correct location of this memory allocation
		// TODO: Consider the creation of a NativeAceArray type
		acl.Entries = make([]ntsd.ACE, count)
		offset := n.Offset()
		limit := uint16(len(b))
		for i := uint16(0); i < count; i++ {
			if offset > limit {
				// FIXME: Panic? Return Error?
				break
			}
			var size uint16
			acl.Entries[i], size = UnmarshalACE(b[offset:]) // FIXME: Use the correct end of the ACE byte slice?
			offset += size
		}
	}
	return acl
}

// UnmarshalACE populates an access control entry from a byte slice containing
// access control entry data formatted according to a Samba NDR data layout.
func UnmarshalACE(b []byte) (ntsd.ACE, uint16) {
	h := NativeACEHeader(b)
	switch h.Type() {
	case ntsd.AccessAllowedControl, ntsd.AccessDeniedControl, ntsd.SystemAuditControl, ntsd.SystemAlarmControl:
		n := NativeACE(b)
		return ntsd.ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
			Mask:  n.Mask(),
			SID:   n.SID(),
		}, h.Size()
	case ntsd.AccessAllowedObjectControl, ntsd.AccessDeniedObjectControl, ntsd.SystemAuditObjectControl, ntsd.SystemAlarmObjectControl:
		n := NativeObjectACE(b)
		return ntsd.ACE{
			Type:        h.Type(),
			Flags:       h.Flags(),
			Mask:        n.Mask(),
			SID:         n.SID(),
			ObjectFlags: n.ObjectFlags(),
			ObjectType:  n.ObjectType(),
		}, h.Size()
	default:
		return ntsd.ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
		}, h.Size()
	}
}

// UnmarshalSID reads a security identifier from a byte slice containing
// security identifier data formatted according to a Samba NDR data layout.
func UnmarshalSID(b []byte) ntsd.SID {
	n := NativeSID(b)
	s := ntsd.SID{
		Revision:            n.Revision(),
		SubAuthorityCount:   n.SubAuthorityCount(), // TODO: Decide whether this is redundant with len(SubAuthority)
		IdentifierAuthority: n.IdentifierAuthority(),
	}
	if s.SubAuthorityCount > ntsd.SidMaxSubAuthorities {
		// TODO: Decide whether this should cause an error
		s.SubAuthorityCount = ntsd.SidMaxSubAuthorities
	}
	s.SubAuthority = make([]uint32, s.SubAuthorityCount)
	for i := uint8(0); i < s.SubAuthorityCount; i++ {
		s.SubAuthority[i] = n.SubAuthority(i)
	}
	return s
}

// UnmarshalGUID reads a globally unique identifier from a byte slice containing
// globally unique identifier data formatted according to a Samba NDR data
// layout.
func UnmarshalGUID(b []byte) ntsd.GUID {
	n := NativeGUID(b)
	return ntsd.GUID{
		n.Byte(0), n.Byte(1), n.Byte(2), n.Byte(3), n.Byte(4), n.Byte(5),
		n.Byte(6), n.Byte(7), n.Byte(8), n.Byte(9), n.Byte(10), n.Byte(11),
		n.Byte(12), n.Byte(13), n.Byte(14), n.Byte(15)}
}
