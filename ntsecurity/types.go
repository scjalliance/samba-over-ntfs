package ntsecurity

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

// SetAlignment sets the alignment data, which is reserved for future use.
func (b NativeSecurityDescriptor) SetAlignment(v uint8) { b[1] = v }

// Control contains the flags qualifying the type of the descriptor and
// providing context for the owner, group, system ACL and discretionary ACL.
func (b NativeSecurityDescriptor) Control() SecurityDescriptorControl {
	return SecurityDescriptorControl(binary.LittleEndian.Uint16(b[2:4]))
}

// SetControl sets the flags qualifying the type of the descriptor and
// providing context for the owner, group, system ACL and discretionary ACL.
func (b NativeSecurityDescriptor) SetControl(v SecurityDescriptorControl) {
	binary.LittleEndian.PutUint16(b[2:4], uint16(v))
}

// OwnerOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) OwnerOffset() uint32 {
	return binary.LittleEndian.Uint32(b[4:8])
}

// SetOwnerOffset sets the offset to a SID representing the object's owner. If
// this is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) SetOwnerOffset(v uint32) {
	binary.LittleEndian.PutUint32(b[4:8], v)
}

// GroupOffset is an offset to a SID representing the object's owner. If this
// is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) GroupOffset() uint32 {
	return binary.LittleEndian.Uint32(b[8:12])
}

// SetGroupOffset sets the offset to a SID representing the object's owner. If
// this is zero, no owner SID is present in the descriptor.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) SetGroupOffset(v uint32) {
	binary.LittleEndian.PutUint32(b[8:12], v)
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

// SetSACLOffset sets the offset to a system ACL. It is only valid if
// SE_SACL_PRESENT is set in the control field. If SE_SACL_PRESENT is set but
// SaclOffset is zero, a NULL ACL is specified.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) SetSACLOffset(v uint32) {
	binary.LittleEndian.PutUint32(b[12:16], v)
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

// SetDACLOffset sets the offset to a discretionary ACL. It is only valid if
// SE_DACL_PRESENT is set in the control field. If SE_DACL_PRESENT is set but
// DaclOffset is zero, a NULL ACL (unconditionally granting access) is
// specified.
//
// The offset is in bytes and is relative to the start of the underlying
// byte stream.
func (b NativeSecurityDescriptor) SetDACLOffset(v uint32) {
	binary.LittleEndian.PutUint32(b[16:20], v)
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

// SetRevision sets the revision level of the security descriptor
//
// Note: Samba actually defines this as a uint16 instead of having a separate
//       alignment byte, but we're keeping them separate here to match NT.
func (b NativeACL) SetRevision(v uint8) { b[0] = v }

// Alignment1 data reserved for future use.
func (b NativeACL) Alignment1() uint8 { return b[1] }

// SetAlignment1 sets alignment data reserved for future use.
func (b NativeACL) SetAlignment1(v uint8) { b[1] = v }

// Alignment2 data reserved for future use.
func (b NativeACL) Alignment2() uint16 { return binary.LittleEndian.Uint16(b[6:8]) }

// SetAlignment2 sets alignment data reserved for future use.
func (b NativeACL) SetAlignment2(v uint16) {
	binary.LittleEndian.PutUint16(b[6:8], v)
}

// Size in bytes of the NativeACL
func (b NativeACL) Size() uint16 {
	return binary.LittleEndian.Uint16(b[2:4])
}

// SetSize sets the size in bytes of the NativeACL
func (b NativeACL) SetSize(v uint16) {
	binary.LittleEndian.PutUint16(b[2:4], v)
}

// Count returns the number of access control entries in the access control
// list.
//
// Note: Samba actually defines this as a uint32 instead of having a separate
//       alignment uint16, but we're keeping them separate here to match NT.
func (b NativeACL) Count() uint16 {
	return binary.LittleEndian.Uint16(b[4:6])
}

// SetCount sets the number of access control entries in the access control
// list.
//
// Note: Samba actually defines this as a uint32 instead of having a separate
//       alignment uint16, but we're keeping them separate here to match NT.
func (b NativeACL) SetCount(v uint16) {
	binary.LittleEndian.PutUint16(b[4:6], v)
}

// Offset is a byte offset to the first access control entry.
//
// The offset is in bytes and is relative to the start of the
// NativeACL.
func (b NativeACL) Offset() uint32 {
	return 8
}

// NativeACEHeader is a byte slice wrapper that acts as a translator
// for the on-disk representation of access control entry headers. One of its
// functions is to convert member values into the appropriate endianness.
type NativeACEHeader []byte

// Type of the access control entry
func (b NativeACEHeader) Type() AccessControlType { return AccessControlType(b[0]) }

// SetType sets the type of the access control entry
func (b NativeACEHeader) SetType(v AccessControlType) {
	b[0] = uint8(v)
}

// Flags describing the access control entry
func (b NativeACEHeader) Flags() AccessControlFlag { return AccessControlFlag(b[1]) }

// SetFlags sets the flags describing the access control entry
func (b NativeACEHeader) SetFlags(v AccessControlFlag) {
	b[1] = uint8(v)
}

// Size in bytes of the access control entry, including the header
func (b NativeACEHeader) Size() uint16 { return binary.LittleEndian.Uint16(b[2:4]) }

// SetSize sets the size in bytes of the access control entry, including the header
func (b NativeACEHeader) SetSize(v uint16) {
	binary.LittleEndian.PutUint16(b[2:4], v)
}

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

// SetMask sets the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeACE) SetMask(v AccessMask) {
	binary.LittleEndian.PutUint32(b[4:8], uint32(v))
}

// SID defines the security identifier that the access control entry applies to.
func (b NativeACE) SID() SID {
	var sid SID
	sid.UnmarshalBinary(b[8:]) // TODO: Decide whether we should leave this dependency here
	return sid
}

// SetSID sets the security identifier that the access control entry applies to.
func (b NativeACE) SetSID(v SID) {
	v.PutBinary(b[8:]) // TODO: Decide whether we should leave this dependency here
}

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

// SetMask sets the access mask of the access control entry, which encapsulates
// the access privileges that the access control entry is specifying.
func (b NativeObjectACE) SetMask(v AccessMask) {
	binary.LittleEndian.PutUint32(b[4:8], uint32(v))
}

// ObjectFlags
func (b NativeObjectACE) ObjectFlags() ObjectAccessControlFlag {
	return ObjectAccessControlFlag(binary.LittleEndian.Uint32(b[8:12]))
}

// SetObjectFlags
func (b NativeObjectACE) SetObjectFlags(v ObjectAccessControlFlag) {
	binary.LittleEndian.PutUint32(b[8:12], uint32(v))
}

// ObjectType
func (b NativeObjectACE) ObjectType() GUID {
	if !b.ObjectFlags().HasFlag(ObjectTypePresent) {
		return GUID{}
	}
	var guid GUID
	guid.UnmarshalBinary(b[12:28]) // TODO: Decide whether we should leave this dependency here
	return guid
}

// SetObjectType
func (b NativeObjectACE) SetObjectType(v GUID) {
	if !b.ObjectFlags().HasFlag(ObjectTypePresent) {
		return
	}
	v.PutBinary(b[12:28]) // TODO: Decide whether we should leave this dependency here
}

func (b NativeObjectACE) InheritedObjectType() GUID {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	if !b.ObjectFlags().HasFlag(InheritedObjectTypePresent) {
		return GUID{}
	}
	var guid GUID
	if b.ObjectFlags().HasFlag(ObjectTypePresent) {
		guid.UnmarshalBinary(b[28:44]) // TODO: Decide whether we should leave this dependency here
	}
	guid.UnmarshalBinary(b[12:28]) // TODO: Decide whether we should leave this dependency here
	return guid
}

func (b NativeObjectACE) SetInheritedObjectType(v GUID) {
	// The location of this member varies based on the flags.
	//
	// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa374857
	if !b.ObjectFlags().HasFlag(InheritedObjectTypePresent) {
		return
	}
	if b.ObjectFlags().HasFlag(ObjectTypePresent) {
		v.PutBinary(b[28:44]) // TODO: Decide whether we should leave this dependency here
	}
	v.PutBinary(b[12:28]) // TODO: Decide whether we should leave this dependency here
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
	var sid SID
	sid.UnmarshalBinary(b[offset:]) // TODO: Decide whether we should leave this dependency here
	return sid
}

// SetSID sets the security identifier that the access control entry applies to.
func (b NativeObjectACE) SetSID(v SID) {
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
	v.PutBinary(b[offset:]) // TODO: Decide whether we should leave this dependency here
}

// NativeSID is a byte slice wrapper that acts as a translator for the on-disk
// representation of security identifiers. One of its functions is to convert
// member values into the appropriate endianness.
type NativeSID []byte

// Revision level of the security identifier.
func (b NativeSID) Revision() uint8 {
	return b[0]
}

// SetRevision sets the revision level of the security identifier.
func (b NativeSID) SetRevision(v uint8) {
	b[0] = v
}

// IdentifierAuthority returns the identifier authority of the security
// identifier.
func (b NativeSID) IdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{b[2], b[3], b[4], b[5], b[6], b[7]} // Big endian
}

// SetIdentifierAuthority sets the identifier authority of the security
// identifier.
func (b NativeSID) SetIdentifierAuthority(v IdentifierAuthority) {
	copy(b[2:8], v[:])
}

// SubAuthorityCount returns the number of SubAuthority elements in the
// security identifier.
func (b NativeSID) SubAuthorityCount() uint8 {
	return b[1]
}

// SubAuthority returns the sub authority of the given index for the security
// identifier.
func (b NativeSID) SubAuthority(index uint8) uint32 {
	start := 8 + int(index)*4
	end := start + 4
	return binary.LittleEndian.Uint32(b[start:end])
}

// SetSubAuthority sets the sub authorities in the security identifier and also
// updates the SubAuthorityCount to match.
func (b NativeSID) SetSubAuthority(v []uint32) {
	// TODO: Verify that len(v) isn't beyond some limit?
	length := len(v)
	b[1] = uint8(length)
	for i := 0; i < length; i++ {
		start := 8 + i*4
		end := start + 4
		binary.LittleEndian.PutUint32(b[start:end], v[i])
	}
}

// NativeGUID is a byte slice wrapper that acts as a translator for the on-disk
// representation of globally unique identifiers. One of its functions is to
// convert member values into the appropriate endianness.
type NativeGUID []byte

func (b NativeGUID) Value() (guid GUID) {
	// See http://en.wikipedia.org/wiki/Globally_unique_identifier
	guid[3] = b[0]
	guid[2] = b[1]
	guid[1] = b[2]
	guid[0] = b[3]
	guid[5] = b[4]
	guid[4] = b[5]
	guid[7] = b[6]
	guid[6] = b[7]
	copy(guid[8:16], b[8:16])
	return
}

func (b NativeGUID) SetValue(v GUID) {
	// See http://en.wikipedia.org/wiki/Globally_unique_identifier
	b[0] = v[3]
	b[1] = v[2]
	b[2] = v[1]
	b[3] = v[0]
	b[4] = v[5]
	b[5] = v[4]
	b[6] = v[7]
	b[7] = v[6]
	copy(b[8:16], v[8:16])
}
