package ntsecurity

// UnmarshalBinary reads a security descriptor from a byte slice containing
// security descriptor data formatted according to an NT data layout.
func (sd *SecurityDescriptor) UnmarshalBinary(data []byte) (err error) {
	n := NativeSecurityDescriptor(data)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	// TODO: Consider direct assignment instead of doing this extra copy operation
	*sd = SecurityDescriptor{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		sd.Owner = new(SID)                                    // FIXME: Validate SID before allocating memory?
		err = sd.Owner.UnmarshalBinary(data[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
		if err != nil {
			return
		}
	}
	if n.GroupOffset() > 0 {
		sd.Group = new(SID)                                    // FIXME: Validate SID before allocating memory?
		err = sd.Group.UnmarshalBinary(data[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
		if err != nil {
			return
		}
	}
	if sd.Control.HasFlag(SACLPresent) && n.SACLOffset() > 0 {
		sd.SACL = new(ACL)                                   // FIXME: Validate ACL before allocating memory?
		err = sd.SACL.UnmarshalBinary(data[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
		if err != nil {
			return
		}
	}
	if sd.Control.HasFlag(DACLPresent) && n.DACLOffset() > 0 {
		sd.DACL = new(ACL)                                   // FIXME: Validate ACL before allocating memory?
		err = sd.DACL.UnmarshalBinary(data[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
		if err != nil {
			return
		}
	}
	return
}

// UnmarshalBinary reads an access control list from a byte slice containing
// access control list data formatted according to an NT data layout.
func (acl *ACL) UnmarshalBinary(data []byte) (err error) {
	n := NativeACL(data)
	// TODO: Consider direct assignment instead of doing this extra copy operation
	*acl = ACL{
		Revision:   n.Revision(),
		Alignment1: n.Alignment1(),
		Alignment2: n.Alignment2(),
	}
	count := n.Count()
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the correct location of this memory allocation
		// TODO: Consider the creation of a NativeAceArray type
		// TODO: Consider reusing the existing array if the length matches
		acl.Entries = make([]ACE, count)
		offset := n.Offset()
		limit := uint16(len(data))
		for i := uint16(0); i < count; i++ {
			if offset > limit {
				// FIXME: Panic? Return Error?
				break
			}
			var size uint16
			size, err = acl.Entries[i].UnmarshalBinary(data[offset:]) // FIXME: Use the correct end of the ACE byte slice?
			offset += size
		}
	}
	return nil
}

// UnmarshalBinary reads an access control entry from a byte slice containing
// access control entry data formatted according to an NT data layout.
func (ace *ACE) UnmarshalBinary(data []byte) (uint16, error) {
	h := NativeACEHeader(data)
	switch h.Type() {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		n := NativeACE(data)
		// TODO: Consider direct assignment instead of doing this extra copy operation
		*ace = ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
			Mask:  n.Mask(),
			SID:   n.SID(),
		}
		return h.Size(), nil
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		n := NativeObjectACE(data)
		// TODO: Consider direct assignment instead of doing this extra copy operation
		*ace = ACE{
			Type:                h.Type(),
			Flags:               h.Flags(),
			Mask:                n.Mask(),
			SID:                 n.SID(),
			ObjectFlags:         n.ObjectFlags(),
			ObjectType:          n.ObjectType(),
			InheritedObjectType: n.InheritedObjectType(),
		}
		return h.Size(), nil
	default:
		// TODO: Decide whether this should return an error
		// TODO: Consider direct assignment instead of doing this extra copy operation
		*ace = ACE{
			Type:  h.Type(),
			Flags: h.Flags(),
		}
		return h.Size(), nil
	}
}

// UnmarshalBinary reads a security identifier from a byte slice containing
// security identifier data formatted according to an NT data layout.
func (sid *SID) UnmarshalBinary(data []byte) error {
	n := NativeSID(data)
	*sid = SID{
		Revision:            n.Revision(),
		SubAuthorityCount:   n.SubAuthorityCount(), // TODO: Decide whether this is redundant with len(SubAuthority)
		IdentifierAuthority: n.IdentifierAuthority(),
	}
	if sid.SubAuthorityCount > SidMaxSubAuthorities {
		// TODO: Decide whether this should cause an error
		sid.SubAuthorityCount = SidMaxSubAuthorities
	}
	// TODO: Consider reusing the existing array if the length matches
	sid.SubAuthority = make([]uint32, sid.SubAuthorityCount)
	for i := uint8(0); i < sid.SubAuthorityCount; i++ {
		sid.SubAuthority[i] = n.SubAuthority(i)
	}
	return nil
}

// UnmarshalBinary reads a globally unique identifier from a byte slice
// containing globally unique identifier data formatted according to an NT
// data layout.
func (guid *GUID) UnmarshalBinary(data []byte) error {
	n := NativeGUID(data)
	// TODO: Consider direct assignment instead of doing this extra copy operation
	*guid = GUID{
		n.Byte(0), n.Byte(1), n.Byte(2), n.Byte(3), n.Byte(4), n.Byte(5),
		n.Byte(6), n.Byte(7), n.Byte(8), n.Byte(9), n.Byte(10), n.Byte(11),
		n.Byte(12), n.Byte(13), n.Byte(14), n.Byte(15)}
	return nil
}
