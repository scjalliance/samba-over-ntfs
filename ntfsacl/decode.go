package ntfsacl

import "encoding/binary"

// NtfsDecodeSecurityDescriptor reads a security descriptor from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func NtfsDecodeSecurityDescriptor(b []byte) *SecurityDescriptor {
	n := NativeSecurityDescriptor(b)
	d := new(SecurityDescriptor)
	d.Revision = n.Revision()
	d.Alignment = n.Alignment()
	d.Control = n.Control()
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Owner = NtfsDecodeSID(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Owner = nil
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Group = NtfsDecodeSID(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Group = nil
	}
	if d.Control.HasFlag(SeSaclPresent) && n.SaclOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Sacl = NtfsDecodeACL(b[n.SaclOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.Sacl = nil
	}
	if d.Control.HasFlag(SeDaclPresent) && n.DaclOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Dacl = NtfsDecodeACL(b[n.DaclOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.Dacl = nil
	}
	return d
}

// NtfsDecodeACL reads an access control list from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func NtfsDecodeACL(b []byte) *ACL {
	n := NativeACL(b)
	acl := new(ACL)
	acl.Revision = n.Revision()
	acl.Alignment1 = n.Alignment1()
	acl.Alignment2 = n.Alignment2()
	count := int(n.AceCount())
	if count > 0 {
		// FIXME: Validate entries before allocating memory?
		// TODO: Consider the correct location of this memory allocation
		// TODO: Consider the creation of a NativeAceArray type
		if len(acl.Entries) != count {
			acl.Entries = make([]ACE, count)
		}
		for i := 0; i < count; i++ {
			// TODO: Decode the access control entries
		}
	} else {
		acl.Entries = nil
	}
	return acl
}

// NtfsDecodeSecurityDescriptorControl reads a security descriptor control from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func NtfsDecodeSecurityDescriptorControl(b []byte) SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// NtfsDecodeSID reads a security identifier from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
func NtfsDecodeSID(b []byte) *SID {
	n := NativeSID(b)
	s := new(SID)
	s.Revision = n.Revision()
	s.SubAuthorityCount = n.SubAuthorityCount()
	if s.SubAuthorityCount > SidMaxSubAuthorities {
		s.SubAuthorityCount = SidMaxSubAuthorities
	}
	s.IdentifierAuthority = n.IdentifierAuthority()
	s.SubAuthority = make([]uint32, s.SubAuthorityCount)
	for i := uint8(0); i < s.SubAuthorityCount; i++ {
		s.SubAuthority[i] = n.SubAuthority(i)
	}
	return s
}
