package ntsecurity

import "errors"

// UnmarshalBinary reads a security descriptor from a byte slice containing
// security descriptor data formatted according to an NT data layout.
func (sd *SecurityDescriptor) UnmarshalBinary(data []byte) (err error) {
	n := NativeSecurityDescriptor(data)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	sd.Revision = n.Revision()
	sd.Alignment = n.Alignment()
	sd.Control = n.Control()
	if n.OwnerOffset() > 0 {
		sd.Owner = new(SID)                                                     // FIXME: Validate SID before allocating memory?
		if err = sd.Owner.UnmarshalBinary(data[n.OwnerOffset():]); err != nil { // FIXME: Use the correct end of the SID byte slice?
			return
		}
	}
	if n.GroupOffset() > 0 {
		sd.Group = new(SID)                                                     // FIXME: Validate SID before allocating memory?
		if err = sd.Group.UnmarshalBinary(data[n.GroupOffset():]); err != nil { // FIXME: Use the correct end of the SID byte slice?
			return
		}
	}
	if sd.Control.HasFlag(SACLPresent) && n.SACLOffset() > 0 {
		sd.SACL = new(ACL)                                                    // FIXME: Validate ACL before allocating memory?
		if err = sd.SACL.UnmarshalBinary(data[n.SACLOffset():]); err != nil { // FIXME: Use the correct end of the ACL byte slice?
			return
		}
	}
	if sd.Control.HasFlag(DACLPresent) && n.DACLOffset() > 0 {
		sd.DACL = new(ACL)                                                    // FIXME: Validate ACL before allocating memory?
		if err = sd.DACL.UnmarshalBinary(data[n.DACLOffset():]); err != nil { // FIXME: Use the correct end of the ACL byte slice?
			return
		}
	}
	return
}

// UnmarshalBinary reads an access control list from a byte slice containing
// access control list data formatted according to an NT data layout.
func (acl *ACL) UnmarshalBinary(data []byte) (err error) {
	n := NativeACL(data)
	acl.Revision = n.Revision()
	acl.Alignment1 = n.Alignment1()
	count := uint32(n.Count())
	acl.Alignment2 = n.Alignment2()
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the creation of a NativeAceArray type
		// TODO: Consider reusing the existing array if the capacity is sufficient
		acl.Entries = make([]ACE, count)
		offset := n.Offset()
		limit := uint32(len(data))
		for i := uint32(0); i < count; i++ {
			if offset > limit {
				return errors.New("ACL data has been corrupted or truncated: ACE offset indicates an address beyond the end of the data")
			}
			var size uint16
			if size, err = acl.Entries[i].UnmarshalBinary(data[offset:]); err != nil { // FIXME: Use the correct end of the ACE byte slice?
				return
			}
			offset += uint32(size)
		}
	}
	return
}

// UnmarshalBinary reads an access control entry from a byte slice containing
// access control entry data formatted according to an NT data layout.
func (ace *ACE) UnmarshalBinary(data []byte) (size uint16, err error) {
	h := NativeACEHeader(data)
	ace.Type = h.Type()
	ace.Flags = h.Flags()
	size = h.Size()
	switch h.Type() {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		n := NativeACE(data)
		ace.Mask = n.Mask()
		ace.SID = n.SID()
		return
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		n := NativeObjectACE(data)
		ace.Mask = n.Mask()
		ace.ObjectFlags = n.ObjectFlags()
		ace.ObjectType = n.ObjectType()
		ace.InheritedObjectType = n.InheritedObjectType()
		ace.SID = n.SID()
		return
	default:
		// TODO: Decide whether this should return an error
		return
	}
}

// UnmarshalBinary reads a security identifier from a byte slice containing
// security identifier data formatted according to an NT data layout.
func (sid *SID) UnmarshalBinary(data []byte) (err error) {
	n := NativeSID(data)
	sid.Revision = n.Revision()
	sid.SubAuthorityCount = n.SubAuthorityCount() // TODO: Decide whether this is redundant with len(SubAuthority)
	sid.IdentifierAuthority = n.IdentifierAuthority()
	if sid.SubAuthorityCount > SidMaxSubAuthorities {
		// TODO: Decide whether this should cause an error
		sid.SubAuthorityCount = SidMaxSubAuthorities
	}
	// TODO: Consider reusing the existing array if the capacity is sufficient
	//       If we do, then we must keep sid.SubAuthorityCount because we can't
	//       rely on len(SubAuthority)
	sid.SubAuthority = make([]uint32, sid.SubAuthorityCount)
	for i := uint8(0); i < sid.SubAuthorityCount; i++ {
		sid.SubAuthority[i] = n.SubAuthority(i)
	}
	return
}

// UnmarshalBinary reads a globally unique identifier from a byte slice
// containing globally unique identifier data formatted according to an NT
// data layout.
func (guid *GUID) UnmarshalBinary(data []byte) (err error) {
	n := NativeGUID(data)
	*guid = n.Value()
	return
}
