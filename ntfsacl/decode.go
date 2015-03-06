package ntfsacl

import "encoding/binary"

// NTFSDecodeSecurityDescriptor reads a security descriptor from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func NTFSDecodeSecurityDescriptor(b []byte) *SecurityDescriptor {
	n := NativeSecurityDescriptor(b)
	d := new(SecurityDescriptor)
	d.Revision = n.Revision()
	d.Alignment = n.Alignment()
	d.Control = n.Control()
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Owner = NTFSDecodeSID(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Owner = nil
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Group = NTFSDecodeSID(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Group = nil
	}
	if d.Control.HasFlag(SACLPresent) && n.SACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.SACL = NTFSDecodeACL(b[n.SACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.SACL = nil
	}
	if d.Control.HasFlag(DACLPresent) && n.DACLOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.DACL = NTFSDecodeACL(b[n.DACLOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.DACL = nil
	}
	return d
}

// NTFSDecodeACL reads an access control list from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func NTFSDecodeACL(b []byte) *ACL {
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

// NTFSDecodeSecurityDescriptorControl reads a security descriptor control from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func NTFSDecodeSecurityDescriptorControl(b []byte) SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// NTFSDecodeSID reads a security identifier from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
func NTFSDecodeSID(b []byte) *SID {
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
