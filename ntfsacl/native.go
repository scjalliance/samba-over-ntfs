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

// SaclOffset is a byte offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) SaclOffset() uint32 {
	return binary.LittleEndian.Uint32(b[12:16])
}

// DaclOffset is a byte offset to a discretionary ACL. It is only valid if
// SE_DACL_PRESENT is set in the control field. If SE_DACL_PRESENT is set but
// DaclOffset is zero, a NULL ACL (unconditionally granting access) is
// specified.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) DaclOffset() uint32 {
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
func (b NativeSidAce) Type() uint8 { return b[0] }

// Flags describing the access control entry
func (b NativeSidAce) Flags() uint8 { return b[1] }

// Size in bytes of the access control entry
func (b NativeSidAce) Size() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// NativeSidAce is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entries that apply to
// security identifiers. One of its functions is to convert member values into
// the appropriate endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeSidAce []byte

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeSidAce) Mask() AccessMask { return AccessMask(binary.LittleEndian.Uint32(b[4:8])) }

// Sid defines the security identifier that the access control entry applies to.
func (b NativeSidAce) Sid() NativeSID { return NativeSID(b[8:]) }

// NativeObjectAce is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entries that apply to
// objects identified by GUIDs. One of its functions is to convert member values
// into the appropriate endianness.
//
// This type expects byte 0 of the underlying slice to be the start of the ACE
// header structure.
type NativeObjectAce []byte

// Mask defines the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeObjectAce) Mask() AccessMask { return AccessMask(binary.LittleEndian.Uint32(b[4:8])) }

// ObjectFlags
func (b NativeObjectAce) ObjectFlags() ObjectAceFlag {
	return ObjectAceFlag(binary.LittleEndian.Uint32(b[8:12]))
}

// ObjectType
func (b NativeObjectAce) ObjectType() NativeGUID {
	return NativeGUID(b[12:28])
}

func (b NativeObjectAce) InheritedObjectType() NativeGUID {
	// FIXME: Determine whether the location of this member varies based on the
	// flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	return NativeGUID(b[28:44])
}

// Sid defines the security identifier that the access control entry applies to.
func (b NativeObjectAce) Sid() NativeSID {
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
func (b NativeSID) IdentifierAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{b[5], b[4], b[3], b[2], b[1], b[0]}
}

// SubAuthority returns the sub authority of the given index for the security
// identifier.
func (b NativeSID) SubAuthority(index uint8) uint32 {
	start := 6 + index*4
	end := start + 4
	return binary.LittleEndian.Uint32(b[start:end])
}

type NativeGUID []byte

// TODO: Write the NativeGUID accessors
// TODO: Figure out the correct byte order for these things
// NOTE: A simple byte index accessor will probably suffice, i.e: guid.Byte(i)
