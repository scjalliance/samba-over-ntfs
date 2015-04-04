package samba

import (
	"errors"

	"go.scj.io/samba-over-ntfs/ntsecurity"
)

// UnmarshalBinary reads a security descriptor from a byte slice containing
// system.NTACL attribute data formatted according to a Samba NDR data layout.
func (sd *SambaSecDescXAttr) UnmarshalBinary(data []byte) error {
	n := NativeXAttr(data)
	//fmt.Printf("%d %d %x %d\n", n.Version(), n.VersionNDR(), b[4:8], n.SecurityDescriptorOffset())
	if !n.Valid() {
		return errors.New("Invalid Samba XAttr Security Descriptor Data")
	}
	if !n.ContainsSecurityDescriptor() {
		// TODO: Decide whether this should be an error
		if sd != nil {
			*sd = SambaSecDescXAttr{} // Is this appropriate?
		}
		return nil
	}
	offset := n.SecurityDescriptorOffset()
	switch n.Version() {
	case 4:
		return (*SambaSecDescV4)(sd).UnmarshalBinary(data[offset:], offset)
	case 3:
		return (*SambaSecDescV3)(sd).UnmarshalBinary(data[offset:], offset)
	case 2:
		return (*SambaSecDescV2)(sd).UnmarshalBinary(data[offset:], offset)
	case 1:
		return (*SambaSecDescV1)(sd).UnmarshalBinary(data[offset:], offset)
	default:
		if sd != nil {
			*sd = SambaSecDescXAttr{} // Is this appropriate?
		}
		return errors.New("Unknown Samba XAttr NTACL Version")
	}
}

// UnmarshalBinary reads a security descriptor from a byte slice containing
// security descriptor and hash data formatted according to a Samba NDR data
// layout version 4.
//
// Offset is the number of bytes that the data slice is offset from the
// beginning of the underlying byte stream. It is subtracted from the relative
// offsets in the security descriptor itself. It is not subtracted from the
// offsets in the ACLs, which are always relative to the start of the security
// descriptor.
func (sd *SambaSecDescV4) UnmarshalBinary(data []byte, offset uint32) error {
	n := NativeSecurityDescriptorHashV4(data)
	sdo := n.SecurityDescriptorOffset()
	//fmt.Printf("%d %d %x %s %d %x %d %x %d\n", binary.LittleEndian.Uint32(b[0:4]), n.HashType(), n.Hash(), n.Description(), n.TimeOffset(), b[n.TimeOffset():n.TimeOffset()+8], n.SysACLHashOffset(), n.SysACLHash(), n.SecurityDescriptorOffset())
	return (*SambaSecDescV1)(sd).UnmarshalBinary(data[sdo:], offset+sdo)
}

// UnmarshalBinary reads a security descriptor from a byte slice containing
// security descriptor and hash data formatted according to a Samba NDR data
// layout version 3.
func (sd *SambaSecDescV3) UnmarshalBinary(data []byte, offset uint32) (err error) {
	// TODO: Write this code or drop support
	return
}

// UnmarshalBinary reads a security descriptor from a byte slice containing
// security descriptor and hash data formatted according to a Samba NDR data
// layout version 2.
func (sd *SambaSecDescV2) UnmarshalBinary(data []byte, offset uint32) (err error) {
	// TODO: Write this code or drop support
	return
}

// UnmarshalBinary reads a security descriptor from a byte slice
// containing security descriptor data formatted according to a Samba NDR data
// layout.
//
// Offset is the number of bytes that the data slice is offset from the
// beginning of the underlying byte stream. It is subtracted from the relative
// offsets in the security descriptor itself. It is not subtracted from the
// offsets in the ACLs, which are always relative to the start of the security
// descriptor.
func (sd *SambaSecDescV1) UnmarshalBinary(data []byte, offset uint32) (err error) {
	n := ntsecurity.NativeSecurityDescriptor(data)
	//fmt.Printf("%d %d %d %d\n", n.OwnerOffset(), n.GroupOffset(), n.SACLOffset(), n.DACLOffset())
	// TODO: Consider direct assignment instead of doing this extra copy operation
	*sd = SambaSecDescV1{
		Revision:  n.Revision(),
		Alignment: n.Alignment(),
		Control:   n.Control(),
	}
	if n.OwnerOffset() > 0 {
		sd.Owner = new(ntsecurity.SID)                                // FIXME: Validate SID before allocating memory?
		err = sd.Owner.UnmarshalBinary(data[n.OwnerOffset()-offset:]) // FIXME: Use the correct end of the SID byte slice?
		if err != nil {
			return
		}
	}
	if n.GroupOffset() > 0 {
		sd.Group = new(ntsecurity.SID)                                // FIXME: Validate SID before allocating memory?
		err = sd.Group.UnmarshalBinary(data[n.GroupOffset()-offset:]) // FIXME: Use the correct end of the SID byte slice?
		if err != nil {
			return
		}
	}
	if sd.Control.HasFlag(ntsecurity.SACLPresent) && n.SACLOffset() > 0 {
		sd.SACL = new(ntsecurity.ACL)                               // FIXME: Validate ACL before allocating memory?
		err = sd.SACL.UnmarshalBinary(data[n.SACLOffset()-offset:]) // FIXME: Use the correct end of the ACL byte slice?
		if err != nil {
			return
		}
	}
	if sd.Control.HasFlag(ntsecurity.DACLPresent) && n.DACLOffset() > 0 {
		sd.DACL = new(ntsecurity.ACL)                               // FIXME: Validate ACL before allocating memory?
		err = sd.DACL.UnmarshalBinary(data[n.DACLOffset()-offset:]) // FIXME: Use the correct end of the ACL byte slice?
		if err != nil {
			return
		}
	}
	return
}
