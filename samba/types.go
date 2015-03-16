package samba

import (
	"bytes"
	"encoding/binary"

	"go.scj.io/samba-over-ntfs/ntsd"
)

// NativeXAttr is a byte slice wrapper that acts as a translator for the
// on-disk representation of Samba NTACL extended attributes. One of its
// functions is to convert member values into the appropriate endianness.
//
// See the definition of xattr_NTACL in samba/librpc/idl/xattr.idl
type NativeXAttr []byte

// Valid returns true if the data is valid, otherwise false
func (b NativeXAttr) Valid() bool {
	if b == nil {
		return false
	}
	if b.Version() != b.VersionNDR() {
		return false
	}
	return true
}

// Version is the Samba security descriptor version that determines the
// encoding format used.
func (b NativeXAttr) Version() uint16 { return binary.LittleEndian.Uint16(b[0:2]) }

// SetVersion sets the Samba security descriptor version that determines
// the encoding format.
func (b NativeXAttr) SetVersion(v uint16) {
	binary.LittleEndian.PutUint16(b[0:2], v) // Version
	binary.LittleEndian.PutUint16(b[2:4], v) // Version for NDR Decoding
}

// VersionNDR is the Samba security descriptor version as encapsulated by the
// network data representation protocol. It should be equal to the value
// returned by Version().
func (b NativeXAttr) VersionNDR() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// ContainsSecurityDescriptor returns true if a security descriptor is present,
// otherwise false.
func (b NativeXAttr) ContainsSecurityDescriptor() bool {
	if binary.LittleEndian.Uint32(b[4:8]) > 0 {
		return true
	}
	return false
}

// SetSecurityDescriptorPresence sets a value indicating the presence of
// security descriptor data.
func (b NativeXAttr) SetSecurityDescriptorPresence(present bool) {
	if present {
		binary.LittleEndian.PutUint32(b[4:8], 0x00020000) // Matches Samba
	} else {
		binary.LittleEndian.PutUint32(b[4:8], 0x00000000)
	}
}

// SecurityDescriptorOffset is an offset to a security descriptor. It is only
// valid if ContainsSecurityDescriptor() is true.
//
// The offset is in bytes and is relative to the start of the
// NativeXAttr.
func (b NativeXAttr) SecurityDescriptorOffset() uint32 { return 8 }

// NativeSecurityDescriptorHashV4 is a byte slice wrapper that acts as a
// translator for security descriptor and hash data formatted according to a
// Samba NDR data layout version 4. One of its functions is to convert member
// values into the appropriate endianness.
//
// See the definition of security_descriptor_hash_v4 in
// samba/librpc/idl/security.idl
type NativeSecurityDescriptorHashV4 []byte

// ContainsSecurityDescriptor returns true if a security descriptor is present,
// otherwise false.
func (b NativeSecurityDescriptorHashV4) ContainsSecurityDescriptor() bool {
	if binary.LittleEndian.Uint32(b[0:4]) > 0 {
		return true
	}
	return false
}

// SetSecurityDescriptorPresence sets a value indicating the presence of
// security descriptor data.
func (b NativeSecurityDescriptorHashV4) SetSecurityDescriptorPresence(present bool) {
	if present {
		binary.LittleEndian.PutUint32(b[0:4], 0x00020004) // Matches Samba
	} else {
		binary.LittleEndian.PutUint32(b[0:4], 0x00000000)
	}
}

// HashType returns the Samba hash type
func (b NativeSecurityDescriptorHashV4) HashType() uint16 { return binary.LittleEndian.Uint16(b[4:6]) }

// Hash returns the 64-byte hash as a byte slice
func (b NativeSecurityDescriptorHashV4) Hash() []uint8 { return b[6:70] }

// Description of the entity responsible for generating the hash.
func (b NativeSecurityDescriptorHashV4) Description() string {
	s := b[70:]
	t := bytes.IndexByte(s, '\x00')
	if t > 0 {
		return string(s[0:t])
	}
	return ""
}

func (b NativeSecurityDescriptorHashV4) TimeOffset() uint32 {
	// FIXME: Return error if no null terminator is found?
	s := b[70:]
	t := bytes.IndexByte(s, '\x00')
	if t >= 0 {
		return uint32(t + 71)
	}
	return uint32(len(b))
}

func (b NativeSecurityDescriptorHashV4) Time() uint64 {
	offset := b.TimeOffset()
	return binary.LittleEndian.Uint64(b[offset : offset+8])
}

func (b NativeSecurityDescriptorHashV4) SysACLHashOffset() uint32 {
	return b.TimeOffset() + 8 // 8 byte NTTIME
}

// Hash returns the 64-byte hash as a byte slice
func (b NativeSecurityDescriptorHashV4) SysACLHash() []uint8 {
	offset := b.SysACLHashOffset()
	return b[offset : offset+64]
}

// SecurityDescriptorOffset is an offset to a security descriptor. It is only
// valid if ContainsSecurityDescriptor() is true.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptorHashV4.
func (b NativeSecurityDescriptorHashV4) SecurityDescriptorOffset() uint32 {
	return b.TimeOffset() + 8 + 64 // 8 byte NTTIME + 64 byte hash
}

// NativeSecurityDescriptorHashV3 is a byte slice wrapper that acts as a
// translator for security descriptor and hash data formatted according to a
// Samba NDR data layout version 3. One of its functions is to convert member
// values into the appropriate endianness.
//
// See the definition of security_descriptor_hash_v3 in
// samba/librpc/idl/security.idl
type NativeSecurityDescriptorHashV3 []byte

// NativeSecurityDescriptorHashV2 is a byte slice wrapper that acts as a
// translator for security descriptor and hash data formatted according to a
// Samba NDR data layout version 2. One of its functions is to convert member
// values into the appropriate endianness.
//
// See the definition of security_descriptor_hash_v2 in
// samba/librpc/idl/security.idl
type NativeSecurityDescriptorHashV2 []byte

// NativeSecurityDescriptor is a byte slice wrapper that acts as a translator
// for security descriptor data formatted according to a Samba NDR data layout
// version 1. One of its functions is to convert member values into the
// appropriate endianness.
//
// See the definition of security_descriptor in samba/librpc/idl/security.idl
type NativeSecurityDescriptor []byte

// Revision is the security descriptor revision level.
func (b NativeSecurityDescriptor) Revision() uint8 { return b[0] }

// SetRevision sets the security descriptor revision level.
func (b NativeSecurityDescriptor) SetRevision(v uint8) { b[0] = v }

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
// NativeXAttr.
func (b NativeSecurityDescriptor) OwnerOffset() uint32 {
	return binary.LittleEndian.Uint32(b[4:8])
}

// GroupOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the
// NativeXAttr.
func (b NativeSecurityDescriptor) GroupOffset() uint32 {
	return binary.LittleEndian.Uint32(b[8:12])
}

// SACLOffset is an offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the
// NativeXAttr.
func (b NativeSecurityDescriptor) SACLOffset() uint32 {
	return binary.LittleEndian.Uint32(b[12:16])
}

// DACLOffset is an offset to a discretionary ACL. It is only valid if
// SE_DACL_PRESENT is set in the control field. If SE_DACL_PRESENT is set but
// DaclOffset is zero, a NULL ACL (unconditionally granting access) is
// specified.
//
// The offset is in bytes and is relative to the start of the
// NativeXAttr.
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
	if !b.ObjectFlags().HasFlag(ntsd.ObjectTypePresent) {
		return ntsd.GUID{}
	}
	return UnmarshalGUID(b[12:28])
}

func (b NativeObjectACE) InheritedObjectType() ntsd.GUID {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	if !b.ObjectFlags().HasFlag(ntsd.InheritedObjectTypePresent) {
		return ntsd.GUID{}
	}
	if b.ObjectFlags().HasFlag(ntsd.ObjectTypePresent) {
		return UnmarshalGUID(b[28:44])
	}
	return UnmarshalGUID(b[12:28])
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeObjectACE) SID() ntsd.SID {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	offset := 12
	if b.ObjectFlags().HasFlag(ntsd.ObjectTypePresent) {
		offset += 16
	}
	if b.ObjectFlags().HasFlag(ntsd.InheritedObjectTypePresent) {
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
func (b NativeSID) IdentifierAuthority() ntsd.IdentifierAuthority {
	return ntsd.IdentifierAuthority{b[2], b[3], b[4], b[5], b[6], b[7]} // Big endian
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
