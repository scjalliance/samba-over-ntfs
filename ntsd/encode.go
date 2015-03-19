package ntsd

const (
	securityDescriptorFixedBytes = 1 + 1 + 2 + 4 + 4 + 4 + 4
	sidFixedBytes                = 1 + 1 + 6
	aclFixedBytes                = 1 + 1 + 2 + 2 + 2
	aceHeaderFixedBytes          = 1 + 1 + 2
	sidACEFixedBytes             = 4
	objectACEFixedBytes          = 4 + 4
)

func MarshalSecurityDescriptorBytes(sd *SecurityDescriptor) int {
	size := securityDescriptorFixedBytes
	size += MarshalSIDBytes(sd.Owner)
	size += MarshalSIDBytes(sd.Group)
	if sd.Control.HasFlag(SACLPresent) {
		size += MarshalACLBytes(sd.SACL)
	}
	if sd.Control.HasFlag(DACLPresent) {
		size += MarshalACLBytes(sd.DACL)
	}
	return size
}

func MarshalACLBytes(acl *ACL) int {
	if acl == nil {
		return 0
	}
	size := aclFixedBytes
	for i := 0; i < len(acl.Entries); i++ {
		size += MarshalACEBytes(&acl.Entries[i])
	}
	return size
}

func MarshalACEBytes(ace *ACE) int {
	size := aceHeaderFixedBytes
	switch ace.Type {
	case AccessAllowedControl, AccessDeniedControl, SystemAuditControl, SystemAlarmControl:
		size += sidACEFixedBytes
		size += MarshalSIDBytes(&ace.SID)
	case AccessAllowedObjectControl, AccessDeniedObjectControl, SystemAuditObjectControl, SystemAlarmObjectControl:
		size += objectACEFixedBytes
		if ace.ObjectFlags.HasFlag(ObjectTypePresent) {
			size += 16
		}
		if ace.ObjectFlags.HasFlag(ObjectTypePresent) {
			size += 16
		}
		size += MarshalSIDBytes(&ace.SID)
	}
	return size
}

func MarshalSIDBytes(sid *SID) int {
	if sid == nil {
		return 0
	}
	return sidFixedBytes + len(sid.SubAuthority)*4
}
