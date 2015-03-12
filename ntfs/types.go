package ntfs

import (
	"encoding/binary"

	"go.scj.io/samba-over-ntfs/ntsd"
)

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
func (b NativeSecurityDescriptor) Control() ntsd.SecurityDescriptorControl {
	return ntsd.SecurityDescriptorControl(binary.LittleEndian.Uint16(b[2:4]))
}

// OwnerOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) OwnerOffset() uint32 {
	return binary.LittleEndian.Uint32(b[4:8])
}

// GroupOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) GroupOffset() uint32 {
	return binary.LittleEndian.Uint32(b[8:12])
}

// SACLOffset is an offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptor.
func (b NativeSecurityDescriptor) SACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[12:16])
}

// DACLOffset is an offset to a discretionary ACL. It is only valid if
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
func (b NativeACL) Alignment2() uint16 { return binary.LittleEndian.Uint16(b[6:8]) }

// Size in bytes of the NativeACL
func (b NativeACL) Size() uint16 {
	return binary.LittleEndian.Uint16(b[2:4])
}

// Count returns the number of access control entries in the access control
// list.
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
func (b NativeACEHeader) Type() ntsd.AccessControlType { return ntsd.AccessControlType(b[0]) }

// Flags describing the access control entry
func (b NativeACEHeader) Flags() ntsd.AccessControlFlag { return ntsd.AccessControlFlag(b[1]) }

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
func (b NativeACE) Mask() ntsd.AccessMask {
	return ntsd.AccessMask(binary.LittleEndian.Uint32(b[4:8]))
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeACE) SID() ntsd.SID { return UnmarshalSID(b[8:]) }

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
func (b NativeObjectACE) Mask() ntsd.AccessMask {
	return ntsd.AccessMask(binary.LittleEndian.Uint32(b[4:8]))
}

// ObjectFlags
func (b NativeObjectACE) ObjectFlags() ntsd.ObjectAccessControlFlag {
	return ntsd.ObjectAccessControlFlag(binary.LittleEndian.Uint32(b[8:12]))
}

// ObjectType
func (b NativeObjectACE) ObjectType() ntsd.GUID {
	return UnmarshalGUID(b[12:28])
}

func (b NativeObjectACE) InheritedObjectType() ntsd.GUID {
	// FIXME: Determine whether the location of this member varies based on the
	// flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	return UnmarshalGUID(b[28:44])
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeObjectACE) SID() ntsd.SID {
	// FIXME: Determine whether the location of this member varies based on the
	// flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	return UnmarshalSID(b[44:])
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
func (b NativeSID) IdentifierAuthority() ntsd.IdentifierAuthority {
	return ntsd.IdentifierAuthority{b[2], b[3], b[4], b[5], b[6], b[7]} // Big endian
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
