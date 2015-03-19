package ntsd

import "encoding/binary"

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice
// containing security descriptor data formatted according to an NT data layout.
func UnmarshalSecurityDescriptor(b []byte) SecurityDescriptor {
	n := NativeSecurityDescriptor(b)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	d := SecurityDescriptor{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Owner = new(SID)
		*d.Owner = UnmarshalSID(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Group = new(SID)
		*d.Group = UnmarshalSID(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if d.Control.HasFlag(SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.SACL = new(ACL)
		*d.SACL = UnmarshalACL(b[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	if d.Control.HasFlag(DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.DACL = new(ACL)
		*d.DACL = UnmarshalACL(b[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	return d
}

// UnmarshalACL reads an access control list from a byte slice containing
// access control list data formatted according to an NT data layout.
func UnmarshalACL(b []byte) ACL {
	n := NativeACL(b)
	acl := ACL{
		Revision:   n.Revision(),
		Alignment1: n.Alignment1(),
		Alignment2: n.Alignment2(),
	}
	count := n.Count()
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the correct location of this memory allocation
		// TODO: Consider the creation of a NativeAceArray type
		acl.Entries = make([]ACE, count)
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
// access control entry data formatted according to an NT data layout.
func UnmarshalACE(b []byte) (ACE, uint16) {
	h := NativeACEHeader(b)
	switch h.Type() {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		n := NativeACE(b)
		return ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
			Mask:  n.Mask(),
			SID:   n.SID(),
		}, h.Size()
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		n := NativeObjectACE(b)
		return ACE{
			Type:                h.Type(),
			Flags:               h.Flags(),
			Mask:                n.Mask(),
			SID:                 n.SID(),
			ObjectFlags:         n.ObjectFlags(),
			ObjectType:          n.ObjectType(),
			InheritedObjectType: n.InheritedObjectType(),
		}, h.Size()
	default:
		return ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
		}, h.Size()
	}
}

// UnmarshalSecurityDescriptorControl reads a security descriptor control from
// a byte slice containing data formatted according to an NT data layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func UnmarshalSecurityDescriptorControl(b []byte) SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// UnmarshalSID reads a security identifier from a byte slice containing
// security identifier data formatted according to an NT data layout.
func UnmarshalSID(b []byte) SID {
	n := NativeSID(b)
	s := SID{
		Revision:            n.Revision(),
		SubAuthorityCount:   n.SubAuthorityCount(), // TODO: Decide whether this is redundant with len(SubAuthority)
		IdentifierAuthority: n.IdentifierAuthority(),
	}
	if s.SubAuthorityCount > SidMaxSubAuthorities {
		// TODO: Decide whether this should cause an error
		s.SubAuthorityCount = SidMaxSubAuthorities
	}
	s.SubAuthority = make([]uint32, s.SubAuthorityCount)
	for i := uint8(0); i < s.SubAuthorityCount; i++ {
		s.SubAuthority[i] = n.SubAuthority(i)
	}
	return s
}

// UnmarshalGUID reads a globally unique identifier from a byte slice containing
// globally unique identifier data formatted according to an NT data layout.
func UnmarshalGUID(b []byte) GUID {
	n := NativeGUID(b)
	return GUID{
		n.Byte(0), n.Byte(1), n.Byte(2), n.Byte(3), n.Byte(4), n.Byte(5),
		n.Byte(6), n.Byte(7), n.Byte(8), n.Byte(9), n.Byte(10), n.Byte(11),
		n.Byte(12), n.Byte(13), n.Byte(14), n.Byte(15)}
}
