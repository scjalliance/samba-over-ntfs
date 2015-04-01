package ntsecurity

const (
	securityDescriptorFixedBytes = 1 + 1 + 2 + 4 + 4 + 4 + 4
	sidFixedBytes                = 1 + 1 + 6
	aclFixedBytes                = 1 + 1 + 2 + 2 + 2
	aceHeaderFixedBytes          = 1 + 1 + 2
	sidACEFixedBytes             = 4
	objectACEFixedBytes          = 4 + 4
)

func (sd *SecurityDescriptor) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sd.BinaryLength())
	err = sd.PutBinary(data)
	return
}

func (sd *SecurityDescriptor) PutBinary(data []byte) (err error) {
	err = nil
	n := NativeSecurityDescriptor(data)
	n.SetRevision(sd.Revision)
	n.SetAlignment(sd.Alignment)
	n.SetControl(sd.Control)
	// Write out the relative offsets
	var offset uint32 = securityDescriptorFixedBytes
	if sd.Owner != nil {
		n.SetOwnerOffset(offset)
		offset += sd.Owner.BinaryLength()
	} else {
		n.SetOwnerOffset(0)
	}
	if sd.Group != nil {
		n.SetGroupOffset(offset)
		offset += sd.Group.BinaryLength()
	} else {
		n.SetGroupOffset(0)
	}
	if sd.Control.HasFlag(SACLPresent) && sd.SACL != nil {
		n.SetSACLOffset(offset)
		offset += sd.SACL.BinaryLength()
	} else {
		n.SetSACLOffset(0)
	}
	if sd.Control.HasFlag(DACLPresent) && sd.DACL != nil {
		n.SetDACLOffset(offset)
		offset += sd.DACL.BinaryLength()
	} else {
		n.SetDACLOffset(0)
	}
	// Write out the data
	offset = securityDescriptorFixedBytes
	if sd.Owner != nil {
		if err = sd.Owner.PutBinary(data[offset:]); err != nil {
			return
		}
		offset += sd.Owner.BinaryLength()
	}
	if sd.Group != nil {
		if err = sd.Group.PutBinary(data[offset:]); err != nil {
			return
		}
		offset += sd.Group.BinaryLength()
	}
	if sd.Control.HasFlag(SACLPresent) && sd.SACL != nil {
		// TODO: Write this
	}
	if sd.Control.HasFlag(DACLPresent) && sd.DACL != nil {
		// TODO: Write this
	}
	return
}

func (sd *SecurityDescriptor) BinaryLength() (size uint32) {
	size = securityDescriptorFixedBytes
	size += sd.Owner.BinaryLength()
	size += sd.Group.BinaryLength()
	if sd.Control.HasFlag(SACLPresent) {
		size += sd.SACL.BinaryLength()
	}
	if sd.Control.HasFlag(DACLPresent) {
		size += sd.DACL.BinaryLength()
	}
	return
}

// MarshalACL reads an access control list from a byte slice containing
// access control list data formatted according to an NT data layout.
func (acl *ACL) MarshalBinary() (data []byte, err error) {
	data = make([]byte, acl.BinaryLength())
	err = acl.PutBinary(data)
	return
}

func (acl *ACL) PutBinary(data []byte) (err error) {
	//n := NativeACL(data)
	err = nil
	// TODO: Write this function
	return
}

func (acl *ACL) BinaryLength() (size uint32) {
	if acl == nil {
		return 0
	}
	size = aclFixedBytes
	for i := 0; i < len(acl.Entries); i++ {
		size += acl.Entries[i].BinaryLength()
	}
	return
}

func (ace *ACE) BinaryLength() (size uint32) {
	size = aceHeaderFixedBytes
	switch ace.Type {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		size += sidACEFixedBytes
		size += ace.SID.BinaryLength()
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		size += objectACEFixedBytes
		if ace.ObjectFlags.HasFlag(ObjectTypePresent) {
			size += 16
		}
		if ace.ObjectFlags.HasFlag(InheritedObjectTypePresent) {
			size += 16
		}
		size += ace.SID.BinaryLength()
	}
	return
}

func (sid *SID) PutBinary(data []byte) (err error) {
	// TODO: Write this
	return
}

func (sid *SID) BinaryLength() uint32 {
	if sid == nil {
		return 0
	}
	return sidFixedBytes + uint32(len(sid.SubAuthority))*4
}
