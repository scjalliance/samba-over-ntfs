package ntfs

import (
	"encoding/binary"

	"go.scj.io/samba-over-ntfs/ntsd"
)

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func UnmarshalSecurityDescriptor(b []byte) ntsd.SecurityDescriptor {
	n := NativeSecurityDescriptor(b)
	d := ntsd.SecurityDescriptor{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Owner = new(ntsd.SID)
		*d.Owner = UnmarshalSID(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		d.Group = new(ntsd.SID)
		*d.Group = UnmarshalSID(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	}
	if d.Control.HasFlag(ntsd.SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.SACL = new(ntsd.ACL)
		*d.SACL = UnmarshalACL(b[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	if d.Control.HasFlag(ntsd.DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		d.DACL = new(ntsd.ACL)
		*d.DACL = UnmarshalACL(b[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	}
	return d
}

// UnmarshalACL reads an access control list from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
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
// data formatted according to an NTFS on-disk data layout.
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

// UnmarshalSecurityDescriptorControl reads a security descriptor control from
// a byte slice containing data formatted according to an NTFS on-disk data
// layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func UnmarshalSecurityDescriptorControl(b []byte) ntsd.SecurityDescriptorControl {
	return ntsd.SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// UnmarshalSID reads a security identifier from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
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
// data formatted according to an NTFS on-disk data layout.
func UnmarshalGUID(b []byte) ntsd.GUID {
	n := NativeGUID(b)
	return ntsd.GUID{
		n.Byte(0), n.Byte(1), n.Byte(2), n.Byte(3), n.Byte(4), n.Byte(5),
		n.Byte(6), n.Byte(7), n.Byte(8), n.Byte(9), n.Byte(10), n.Byte(11),
		n.Byte(12), n.Byte(13), n.Byte(14), n.Byte(15)}
}
