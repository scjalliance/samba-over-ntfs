package ntfsacl

import "encoding/binary"

// NtfsDecode reads a security descriptor from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func (d SecurityDescriptor) NtfsDecode(b []byte) {
	n := NativeSecurityDescriptor(b)
	d.Revision = n.Revision()
	d.Alignment = n.Alignment()
	d.Control = n.Control()
	if n.OwnerOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Owner = new(SID)
		d.Owner.NtfsDecode(b[n.OwnerOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Owner = nil
	}
	if n.GroupOffset() > 0 {
		// FIXME: Validate SID before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		d.Group = new(SID)
		d.Group.NtfsDecode(b[n.GroupOffset():]) // FIXME: Use the correct end of the SID byte slice?
	} else {
		d.Group = nil
	}
	if d.Control.HasFlag(SeSaclPresent) && n.SaclOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		if d.Sacl == nil {
			d.Sacl = new(ACL)
		}
		d.Sacl.NtfsDecode(b[n.SaclOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.Sacl = nil
	}
	if d.Control.HasFlag(SeDaclPresent) && n.DaclOffset() > 0 {
		// FIXME: Validate ACL before allocating memory?
		// TODO: Consider moving the memory allocation to NtfsDecode.
		if d.Dacl == nil {
			d.Dacl = new(ACL)
		}
		d.Dacl.NtfsDecode(b[n.DaclOffset():]) // FIXME: Use the correct end of the ACL byte slice?
	} else {
		d.Dacl = nil
	}
}

// NtfsDecode reads an access control list from a byte slice containing data
// formatted according to an NTFS on-disk data layout.
func (acl ACL) NtfsDecode(b []byte) {
	n := NativeACL(b)
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
}

// NtfsDecode reads a security descriptor control from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
//
// TODO: Decide whether this is redundant in light of the Control() function
// on the NativeSecurityDescriptor type.
func (c SecurityDescriptorControl) NtfsDecode(b []byte) {
	c = SecurityDescriptorControl(binary.LittleEndian.Uint16(b[0:2]))
}

// NtfsDecode reads a security identifier from a byte slice containing
// data formatted according to an NTFS on-disk data layout.
func (s SID) NtfsDecode(b []byte) {
	n := NativeSID(b)
	// TODO: Write the mapping code
}
