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
	// TODO: Write this
	return
}

func (sd *SecurityDescriptor) BinaryLength() (size int) {
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

func (acl *ACL) BinaryLength() int {
	if acl == nil {
		return 0
	}
	size := aclFixedBytes
	for i := 0; i < len(acl.Entries); i++ {
		size += acl.Entries[i].BinaryLength()
	}
	return size
}

func (ace *ACE) BinaryLength() int {
	size := aceHeaderFixedBytes
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
	return size
}

func (sid *SID) BinaryLength() int {
	if sid == nil {
		return 0
	}
	return sidFixedBytes + len(sid.SubAuthority)*4
}
