package ntfsacl

import "encoding/binary"

// NativeSecurityDescriptor is a byte slice wrapper that acts as a translator
// for the on-disk representation of security descriptors. One of its functions
// is to convert member values into the appropriate endianness.
type NativeSecurityDescriptor []byte

// Revision level of the security descriptor.
func (b NativeSecurityDescriptor) Revision() uint8 { return b[0] }

// Alignment data reserved for future use.
func (b NativeSecurityDescriptor) Alignment() uint8 { return b[1] }

// Control contains the flags qualifying the type of the descriptor and
// providing context for the owner, group, system ACL and discretionary ACL.
func (b NativeSecurityDescriptor) Control() SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[2:4]))
}

// OwnerOffset is a byte offset to a SID representing an object's owner. If this
// is NULL, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) OwnerOffset() uint32 {
	return binary.LittleEndian.Uint32(b[4:8])
}

// GroupOffset is a byte offset to a SID representing an object's owner. If this
// is NULL, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) GroupOffset() uint32 {
	return binary.LittleEndian.Uint32(b[8:12])
}

// SACLOffset is a byte offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) SACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[12:16])
}

// DACLOffset is a byte offset to a discretionary ACL. It is only valid if
// SE_DACL_PRESENT is set in the control field. If SE_DACL_PRESENT is set but
// DaclOffset is zero, a NULL ACL (unconditionally granting access) is
// specified.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) DACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[16:20])
}

// NativeACL is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control lists. One of its functions
// is to convert member values into the appropriate endianness.
type NativeACL []byte

// Revision level of the security descriptor
func (b NativeACL) Revision() uint8 { return b[0] }

// Alignment1 data reserved for future use.
func (b NativeACL) Alignment1() uint8 { return b[1] }

// Alignment2 data reserved for future use.
func (b NativeACL) Alignment2() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// Size in bytes of the NativeACL
func (b NativeACL) Size() uint16 {
	return binary.LittleEndian.Uint16(b[2:4])
}

// AceCount is the number of access control entries in the access control list.
func (b NativeACL) AceCount() uint16 {
	return binary.LittleEndian.Uint16(b[4:6])
}

// NativeAceHeader is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entry headers. One of its
// functions is to convert member values into the appropriate endianness.
type NativeAceHeader []byte

// Type of the access control entry
func (b NativeAceHeader) Type() uint8 { return b[0] }

// Flags describing the access control entry
func (b NativeAceHeader) Flags() uint8 { return b[1] }

// Size in bytes of the access control entry
func (b NativeAceHeader) Size() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// NativeSidACE is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entries that apply to
// security identifiers. One of its functions is to convert member values into
// the appropriate endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeSidACE []byte

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeSidACE) Mask() AccessMask { return AccessMask(binary.LittleEndian.Uint32(b[4:8])) }

// Sid defines the security identifier that the access control entry applies to.
func (b NativeSidACE) Sid() NativeSID { return NativeSID(b[8:]) }

// NativeObjectACE is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entries that apply to
// objects identified by GUIDs. One of its functions is to convert member values
// into the appropriate endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeObjectACE []byte

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeObjectACE) Mask() AccessMask { return AccessMask(binary.LittleEndian.Uint32(b[4:8])) }

// ObjectFlags
func (b NativeObjectACE) ObjectFlags() ObjectAccessControlFlag {
	return ObjectAccessControlFlag(binary.LittleEndian.Uint32(b[8:12]))
}

// ObjectType
func (b NativeObjectACE) ObjectType() NativeGUID {
	return NativeGUID(b[12:28])
}

func (b NativeObjectACE) InheritedObjectType() NativeGUID {
	// FIXME: Determine whether the location of this member varies based on the
	// flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	return NativeGUID(b[28:44])
}

// Sid defines the security identifier that the access control entry applies to.
func (b NativeObjectACE) SID() NativeSID {
	// FIXME: Determine whether the location of this member varies based on the
	// flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	return NativeSID(b[44:])
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
	start := 8 + index*4
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

// TODO: Write the NativeGUID accessors
// NOTE: A simple byte index accessor will probably suffice, i.e: guid.Byte(i)
