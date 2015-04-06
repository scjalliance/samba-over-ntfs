package ntsecurity

import (
	"errors"
	"math"
)

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
	n := NativeSecurityDescriptor(data)
	n.SetRevision(sd.Revision)
	n.SetAlignment(sd.Alignment)
	n.SetControl(sd.Control) // TODO: Consider enforcing SelfRelative

	// Write out the relative offsets
	offset := uint32(securityDescriptorFixedBytes)
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
		if err = sd.SACL.PutBinary(data[offset:]); err != nil {
			return
		}
		offset += sd.SACL.BinaryLength()
	}
	if sd.Control.HasFlag(DACLPresent) && sd.DACL != nil {
		if err = sd.DACL.PutBinary(data[offset:]); err != nil {
			return
		}
		offset += sd.DACL.BinaryLength()
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

// MarshalBinary writes an access control list to a byte slice containing
// access control list data formatted according to an NT data layout.
func (acl *ACL) MarshalBinary() (data []byte, err error) {
	data = make([]byte, acl.BinaryLength())
	err = acl.PutBinary(data)
	return
}

func (acl *ACL) PutBinary(data []byte) (err error) {
	n := NativeACL(data)

	size := acl.BinaryLength()
	if size > math.MaxUint16 {
		err = errors.New("Access control entry is too large to encode properly: Size exceeds MaxUint16")
		return
	}

	count := len(acl.Entries)
	if count > math.MaxUint16 {
		return errors.New("Access control list has too many entries to encode properly: Count exceeds MaxUint16")
	}

	n.SetRevision(acl.Revision)
	n.SetAlignment1(acl.Alignment1)
	n.SetSize(uint16(size))
	n.SetCount(uint16(count))
	n.SetAlignment2(acl.Alignment2)
	offset := n.Offset()
	for i := 0; i < count; i++ {
		//fmt.Printf("%d %d %d %v\n", i, count, offset, acl.Entries[i].SID.String())
		var size uint16
		if size, err = acl.Entries[i].PutBinary(data[offset:]); err != nil { // FIXME: Use the correct end of the ACE byte slice?
			return
		}
		offset += uint32(size)
	}
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

func (ace *ACE) MarshalBinary() (data []byte, err error) {
	data = make([]byte, ace.BinaryLength())
	_, err = ace.PutBinary(data)
	return
}

func (ace *ACE) PutBinary(data []byte) (size uint16, err error) {
	bl := ace.BinaryLength()
	if bl > math.MaxUint16 {
		err = errors.New("Access control entry is too large to encode properly: Size exceeds MaxUint16")
		return
	}
	size = uint16(bl)

	h := NativeACEHeader(data)
	h.SetType(ace.Type)
	h.SetFlags(ace.Flags)
	h.SetSize(size)

	switch ace.Type {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		n := NativeACE(data)
		n.SetMask(ace.Mask)
		n.SetSID(ace.SID)
		//fmt.Printf("%v %v %v\n", ace.Type, ace.SID.String(), n.SID().String())
		return
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		n := NativeObjectACE(data)
		n.SetMask(ace.Mask)
		n.SetObjectFlags(ace.ObjectFlags)
		if ace.ObjectFlags.HasFlag(ObjectTypePresent) {
			n.SetObjectType(ace.ObjectType)
		}
		if ace.ObjectFlags.HasFlag(InheritedObjectTypePresent) {
			n.SetInheritedObjectType(ace.InheritedObjectType)
		}
		n.SetSID(ace.SID)
		return
	default:
		// TODO: Decide whether this should return an error
		return
	}
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
	n := NativeSID(data)
	n.SetRevision(sid.Revision)
	n.SetIdentifierAuthority(sid.IdentifierAuthority)
	n.SetSubAuthority(sid.SubAuthority)
	return
}

func (sid *SID) BinaryLength() (size uint32) {
	if sid == nil {
		return 0
	}
	size = sidFixedBytes
	size += uint32(len(sid.SubAuthority)) * 4
	return
}

func (guid *GUID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, guid.BinaryLength())
	err = guid.PutBinary(data)
	return
}

func (guid *GUID) PutBinary(data []byte) (err error) {
	n := NativeGUID(data)
	n.SetValue(*guid)
	return
}

func (guid *GUID) BinaryLength() (size uint32) {
	return 16
}
