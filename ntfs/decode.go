package ntfs

import (
	"encoding/binary"

	"go.scj.io/samba-over-ntfs/ntsd"
)

// UnmarshalSecurityDescriptor reads a security descriptor from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func UnmarshalSecurityDescriptor(b []byte) *ntsd.SecurityDescriptor {
	n := NativeSecurityDescriptor(b)
	d := new(ntsd.SecurityDescriptor)
	d.Revision = n.Revision()
	d.Alignment = n.Alignment()
	d.Control = n.Control()
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Owner = UnmarshalSID(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Owner = nil
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Group = UnmarshalSID(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Group = nil
	}
	if d.Control.HasFlag(ntsd.SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.SACL = UnmarshalACL(b[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.SACL = nil
	}
	if d.Control.HasFlag(ntsd.DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.DACL = UnmarshalACL(b[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.DACL = nil
	}
	return d
}

// UnmarshalACL reads an access control list from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func UnmarshalACL(b []byte) *ntsd.ACL {
	n := NativeACL(b)
	acl := new(ntsd.ACL)
	acl.Revision = n.Revision()
	acl.Alignment1 = n.Alignment1()
	acl.Alignment2 = n.Alignment2()
	count := int(n.AceCount())
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the correct location of this memory allocation
		// TODO: Consider the creation of a NativeAceArray type
		if len(acl.Entries) != count {
			acl.Entries = make([]ntsd.ACE, count)
		}
		for i := 0; i < count; i++ {
			// TODO: Decode the access control entries
		}
	} else {
		acl.Entries = nil
	}
	return acl
}

// UnmarshalSecurityDescriptorControl reads a security descriptor control from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func UnmarshalSecurityDescriptorControl(b []byte) ntsd.SecurityDescriptorControl {
	return ntsd.SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// UnmarshalSID reads a security identifier from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
func UnmarshalSID(b []byte) *ntsd.SID {
	n := NativeSID(b)
	s := new(ntsd.SID)
	s.Revision = n.Revision()
	s.SubAuthorityCount = n.SubAuthorityCount()
	if s.SubAuthorityCount > ntsd.SidMaxSubAuthorities {
		s.SubAuthorityCount = ntsd.SidMaxSubAuthorities
	}
	s.IdentifierAuthority = n.IdentifierAuthority()
	s.SubAuthority = make([]uint32, s.SubAuthorityCount)
	for i := uint8(0); i < s.SubAuthorityCount; i++ {
		s.SubAuthority[i] = n.SubAuthority(i)
	}
	return s
}
