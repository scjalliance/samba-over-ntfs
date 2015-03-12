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
	if binary.LittleEndian.Uint16(b[4:8]) > 0 {
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
	if binary.LittleEndian.Uint16(b[0:4]) > 0 {
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
		return uint32(t + 1)
	}
	return uint32(len(b))
}

func (b NativeSecurityDescriptorHashV4) Time() uint64 {
	offset := b.TimeOffset()
	return binary.LittleEndian.Uint64(b[offset : offset+8])
}

// SecurityDescriptorOffset is an offset to a security descriptor. It is only
// valid if ContainsSecurityDescriptor() is true.
//
// The offset is in bytes and is relative to the start of the
// NativeSecurityDescriptorHashV4.
func (b NativeSecurityDescriptorHashV4) SecurityDescriptorOffset() uint32 {
	// TODO: Make sure byte alignment rules don't bite us here
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

// Control contains the flags qualifying the type of the descriptor and
// providing context for the owner, group, system ACL and discretionary ACL.
func (b NativeSecurityDescriptor) Control() ntsd.SecurityDescriptorControl {
	return ntsd.SecurityDescriptorControl(binary.LittleEndian.Uint16(b[1:3]))
}
