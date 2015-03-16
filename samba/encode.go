package samba

import "go.scj.io/samba-over-ntfs/ntsd"

func MarshalXAttr(sd ntsd.SecurityDescriptor, b []byte) {
	// TODO: Write this
}

func MarshalSecurityDescriptorV4(sd ntsd.SecurityDescriptor, b []byte) {
	// TODO: Write this
}

func MarshalSecurityDescriptor(sd ntsd.SecurityDescriptor, b []byte) {
	// TODO: Write this
}

const (
	XattrDescription = "ntfs"
)

const (
	xattrFixedBytes                = 2 + 2 + 4
	securityDescriptorV4FixedBytes = 4 + 2 + 64 + len(XattrDescription) + 8 + 64
	securityDescriptorFixedBytes   = 1 + 1 + 2 + 4 + 4 + 4 + 4
	sidFixedBytes                  = 1 + 1 + 6
	aclFixedBytes                  = 1 + 1 + 2 + 2 + 2
	aceHeaderFixedBytes            = 1 + 1 + 2
	sidACEFixedBytes               = 4
	objectACEFixedBytes            = 4 + 4
)

func MarshalXattrBytes(sd *ntsd.SecurityDescriptor) int {
	return xattrFixedBytes + MarshalSecurityDescriptorV4Bytes(sd)
}

func MarshalSecurityDescriptorV4Bytes(sd *ntsd.SecurityDescriptor) int {
	return securityDescriptorV4FixedBytes + MarshalSecurityDescriptorBytes(sd)
}

func MarshalSecurityDescriptorBytes(sd *ntsd.SecurityDescriptor) int {
	size := securityDescriptorFixedBytes
	size += MarshalSIDBytes(sd.Owner)
	size += MarshalSIDBytes(sd.Group)
	if sd.Control.HasFlag(ntsd.SACLPresent) {
		size += MarshalACLBytes(sd.SACL)
	}
	if sd.Control.HasFlag(ntsd.DACLPresent) {
		size += MarshalACLBytes(sd.DACL)
	}
	return size
}

func MarshalACLBytes(acl *ntsd.ACL) int {
	if acl == nil {
		return 0
	}
	size := aclFixedBytes
	for i := 0; i < len(acl.Entries); i++ {
		size += MarshalACEBytes(&acl.Entries[i])
	}
	return size
}

func MarshalACEBytes(ace *ntsd.ACE) int {
	size := aceHeaderFixedBytes
	switch ace.Type {
	case ntsd.AccessAllowedControl, ntsd.AccessDeniedControl, ntsd.SystemAuditControl, ntsd.SystemAlarmControl:
		size += sidACEFixedBytes
		size += MarshalSIDBytes(&ace.SID)
	case ntsd.AccessAllowedObjectControl, ntsd.AccessDeniedObjectControl, ntsd.SystemAuditObjectControl, ntsd.SystemAlarmObjectControl:
		size += objectACEFixedBytes
		if ace.ObjectFlags.HasFlag(ntsd.ObjectTypePresent) {
			size += 16
		}
		if ace.ObjectFlags.HasFlag(ntsd.ObjectTypePresent) {
			size += 16
		}
		size += MarshalSIDBytes(&ace.SID)
	}
	return size
}

func MarshalSIDBytes(sid *ntsd.SID) int {
	if sid == nil {
		return 0
	}
	return sidFixedBytes + len(sid.SubAuthority)*4
}
