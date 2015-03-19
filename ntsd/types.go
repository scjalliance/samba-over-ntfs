package ntsd

import "encoding/binary"

// NativeSecurityDescriptor is a byte slice wrapper that acts as a translator
// for the NT-style representation of security descriptors. One of its functions
// is to convert member values into the appropriate endianness.
type NativeSecurityDescriptor []byte

// Revision is the security descriptor revision level.
func (b NativeSecurityDescriptor) Revision() uint8 { return b[0] }

// SetRevision sets the security descriptor revision level.
func (b NativeSecurityDescriptor) SetRevision(v uint8) { b[0] = v }

// Alignment data reserved for future use.
func (b NativeSecurityDescriptor) Alignment() uint8 { return b[1] }

// Control contains the flags qualifying the type of the descriptor and
// providing context for the owner, group, system ACL and discretionary ACL.
func (b NativeSecurityDescriptor) Control() SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[2:4]))
}

// OwnerOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) OwnerOffset() uint32 {
	return binary.LittleEndian.Uint32(b[4:8])
}

// GroupOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) GroupOffset() uint32 {
	return binary.LittleEndian.Uint32(b[8:12])
}

// SACLOffset is an offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) SACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[12:16])
}

// DACLOffset is an offset to a discretionary ACL. It is only valid if
// SE_DACL_PRESENT is set in the control field. If SE_DACL_PRESENT is set but
// DaclOffset is zero, a NULL ACL (unconditionally granting access) is
// specified.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) DACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[16:20])
}

// NativeACL is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control lists. One of its functions
// is to convert member values into the appropriate endianness.
type NativeACL []byte

// Revision level of the security descriptor
//
// Note: Samba actually defines this as a uint16 instead of having a separate
//       alignment byte, but we're keeping them separate here to match NT.
func (b NativeACL) Revision() uint8 { return b[0] }

// Alignment1 data reserved for future use.
func (b NativeACL) Alignment1() uint8 { return b[1] }

// Alignment2 data reserved for future use.
func (b NativeACL) Alignment2() uint16 { return binary.LittleEndian.Uint16(b[6:8]) }

// Size in bytes of the NativeACL
func (b NativeACL) Size() uint16 {
	return binary.LittleEndian.Uint16(b[2:4])
}

// Count returns the number of access control entries in the access control
// list.
//
// Note: Samba actually defines this as a uint32 instead of having a separate
//       alignment uint16, but we're keeping them separate here to match NT.
func (b NativeACL) Count() uint16 {
	return binary.LittleEndian.Uint16(b[4:6])
}

// Offset is a byte offset to the first access control entry.
//
// The offset is in bytes and is relative to the start of the
// NativeACL.
func (b NativeACL) Offset() uint16 {
	return 8
}

// NativeACEHeader is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entry headers. One of its
// functions is to convert member values into the appropriate endianness.
type NativeACEHeader []byte

// Type of the access control entry
func (b NativeACEHeader) Type() AccessControlType { return AccessControlType(b[0]) }

// Flags describing the access control entry
func (b NativeACEHeader) Flags() AccessControlFlag { return AccessControlFlag(b[1]) }

// Size in bytes of the access control entry
func (b NativeACEHeader) Size() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// NativeACE is a byte slice wrapper that acts as a translator for the on-disk
// representation of access control entries that apply to security identifiers.
// One of its functions is to convert member values into the appropriate
// endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeACE NativeACEHeader

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeACE) Mask() AccessMask {
	return AccessMask(binary.LittleEndian.Uint32(b[4:8]))
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeACE) SID() SID { return UnmarshalSID(b[8:]) }

// NativeObjectACE is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entries that apply to
// objects identified by GUIDs. One of its functions is to convert member values
// into the appropriate endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeObjectACE NativeACEHeader

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeObjectACE) Mask() AccessMask {
	return AccessMask(binary.LittleEndian.Uint32(b[4:8]))
}

// ObjectFlags
func (b NativeObjectACE) ObjectFlags() ObjectAccessControlFlag {
	return ObjectAccessControlFlag(binary.LittleEndian.Uint32(b[8:12]))
}

// ObjectType
func (b NativeObjectACE) ObjectType() GUID {
	if !b.ObjectFlags().HasFlag(ObjectTypePresent) {
		return GUID{}
	}
	return UnmarshalGUID(b[12:28])
}

func (b NativeObjectACE) InheritedObjectType() GUID {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	if !b.ObjectFlags().HasFlag(InheritedObjectTypePresent) {
		return GUID{}
	}
	if b.ObjectFlags().HasFlag(ObjectTypePresent) {
		return UnmarshalGUID(b[28:44])
	}
	return UnmarshalGUID(b[12:28])
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeObjectACE) SID() SID {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	offset := 12
	if b.ObjectFlags().HasFlag(ObjectTypePresent) {
		offset += 16
	}
	if b.ObjectFlags().HasFlag(InheritedObjectTypePresent) {
		offset += 16
	}
	return UnmarshalSID(b[offset:])
}

// NativeSID is a byte slice wrapper that acts as a translator for the on-disk
// representation of security identifiers. One of its functions is to convert
// member values into the appropriate endianness.
type NativeSID []byte

// Revision level of the security identifier.
func (b NativeSID) Revision() uint8 {
	return b[0]
}

// SubAuthorityCount returns the number of SubAuthority elements in the
// security identifier.
func (b NativeSID) SubAuthorityCount() uint8 {
	return b[1]
}

// IdentifierAuthority returns the identifier authority of the security
// identifier.
func (b NativeSID) IdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{b[2], b[3], b[4], b[5], b[6], b[7]} // Big endian
}

// SubAuthority returns the sub authority of the given index for the security
// identifier.
func (b NativeSID) SubAuthority(index uint8) uint32 {
	start := 8 + int(index)*4
	end := start + 4
	return binary.LittleEndian.Uint32(b[start:end])
}

// NativeGUID is a byte slice wrapper that acts as a translator for the on-disk
// representation of globally unique identifiers. One of its functions is to
// convert member values into the appropriate endianness.
type NativeGUID []byte

// Byte returns the byte of the GUID at the given index
func (b NativeGUID) Byte(index uint8) byte {
	// TODO: Verify that we have the correct byte order for these things
	switch {
	case index >= 8:
		return b[index]
	case index >= 6:
		return b[13-index] // Swap little-endian bytes 6 and 7
	case index >= 4:
		return b[9-index] // Swap little-endian bytes 4 and 5
	default:
		return b[3-index] // Swap little-endian bytes 0 through 3
	}
}
