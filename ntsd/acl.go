package ntsd

import (
	"encoding/hex"
	"fmt"
)

type SecurityDescriptor struct {
	Revision  uint8
	Alignment uint8
	Control   SecurityDescriptorControl
	Owner     *SID
	Group     *SID
	SACL      *ACL
	DACL      *ACL
}

// The SID structure is a variable-length structure used to uniquely identify
// users or groups. SID stands for security identifier.
//
// The standard textual representation of the SID is of the form:
// S-R-I-S-S...
// Where:
// - The first "S" is the literal character 'S' identifying the following
// digits as a SID.
// - R is the revision level of the SID expressed as a sequence of digits
// in decimal.
// - I is the 48-bit IdentifierAuthority, expressed as digits in decimal,
// if I < 2^32, or hexadecimal prefixed by "0x", if I >= 2^32.
// - S... is one or more sub_authority values, expressed as digits in
// decimal.
//
// Example SID; the domain-relative SID of the local Administrators group on
// Windows NT/2k:
//  S-1-5-32-544
// This translates to a SID with:
//  Revision = 1
//  SubAuthorityCount = 2
//  IdentifierAuthority = {0,0,0,0,0,5} // SECURITY_NT_AUTHORITY
//  SubAuthority[0] = 32                // SECURITY_BUILTIN_DOMAIN_RID
//  SubAuthority[1] = 544               // DOMAIN_ALIAS_RID_ADMINS
type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8 // TODO: Consider removing this and just using len(SubAuthority)
	IdentifierAuthority IdentifierAuthority
	SubAuthority        []uint32
}

const (
	// SidMinRevision indicates the minimum SID revision supported by the ntfsacl
	// package
	SidMinRevision = 1
	// SidMaxRevision indicates the maximum SID revision supported by the ntfsacl
	// package
	SidMaxRevision = 1
	// SidMaxSubAuthorities indicates the maximum number of subauthorities
	// supported by the ntfsacl package
	SidMaxSubAuthorities = 15
)

func (sid SID) String() (output string) {
	output = "S-"
	output += fmt.Sprint(sid.Revision)
	output += "-"
	output += fmt.Sprint(sid.IdentifierAuthority.Uint64())
	for _, subAuth := range sid.SubAuthority {
		output += "-"
		output += fmt.Sprint(subAuth)
	}
	return
}

// An ACL starts with an ACL header structure, which specifies the size of
// the ACL and the number of ACEs it contains. The ACL header is followed by
// zero or more access control entries (ACEs). The ACL as well as each ACE
// are aligned on 4-byte boundaries.
//
// A preferred order of the ACE objects must be enforced in order for the ACL
// to provide the intended safeguards. See
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379298
// for details.
type ACL struct {
	Revision   uint8
	Alignment1 uint8
	Alignment2 uint16
	Entries    []ACE
}

const (
	MinACLRevision = 2
	MaxACLRevision = 4
)

// An ACE is an access-control entry in an access-control list (ACL).
// An ACE defines access to an object for a specific user or group or defines
// the types of access that generate system-administration messages or alarms
// for a specific user or group. The user or group is identified by a security
// identifier (SID).
type ACE struct {
	Type                AccessControlType
	Flags               AccessControlFlag
	Mask                AccessMask
	SID                 SID
	ObjectFlags         ObjectAccessControlFlag
	ObjectType          GUID
	InheritedObjectType GUID
}

// SecurityDescriptorControl stores descriptor control flags, which guide the
// interpretation of security descriptors.
type SecurityDescriptorControl uint16

const (
	// SeOwnerDefaulted is a boolean flag which, when set, indicates that the
	// SID pointed to by the Owner field was provided by a
	// defaulting mechanism rather than explicitly provided by the
	// original provider of the security descriptor. This may
	// affect the treatment of the SID with respect to inheritance
	// of an owner.
	OwnerDefaulted SecurityDescriptorControl = 0x0001

	// SeGroupDefaulted is a boolean flag which, when set, indicates that the
	// SID in the Group field was provided by a defaulting mechanism
	// rather than explicitly provided by the original provider of
	// the security descriptor.  This may affect the treatment of
	// the SID with respect to inheritance of a primary group.
	GroupDefaulted SecurityDescriptorControl = 0x0002

	// SeDaclPresent is a boolean flag which, when set, indicates that the
	// security descriptor contains a discretionary ACL. If this
	// flag is set and the Dacl field of the SECURITY_DESCRIPTOR is
	// null, then a null ACL is explicitly being specified.
	DACLPresent SecurityDescriptorControl = 0x0004

	// SeDaclDefaulted is a boolean flag which, when set, indicates that the
	// ACL pointed to by the Dacl field was provided by a defaulting
	// mechanism rather than explicitly provided by the original
	// provider of the security descriptor. This may affect the
	// treatment of the ACL with respect to inheritance of an ACL.
	// This flag is ignored if the DaclPresent flag is not set.
	DACLDefaulted SecurityDescriptorControl = 0x0008

	// SeSaclPresent is a boolean flag which, when set, indicates that the
	// security descriptor contains a system ACL pointed to by the
	// Sacl field. If this flag is set and the Sacl field of the
	// SECURITY_DESCRIPTOR is null, then an empty (but present)
	// ACL is being specified.
	SACLPresent SecurityDescriptorControl = 0x0010

	// SeSaclDefaulted is a boolean flag which, when set, indicates that the
	// ACL pointed to by the Sacl field was provided by a defaulting
	// mechanism rather than explicitly provided by the original
	// provider of the security descriptor. This may affect the
	// treatment of the ACL with respect to inheritance of an ACL.
	// This flag is ignored if the SaclPresent flag is not set.
	SACLDefaulted SecurityDescriptorControl = 0x0020

	DACLAutoInheritReq SecurityDescriptorControl = 0x0100
	SACLAutoInheritReq SecurityDescriptorControl = 0x0200
	DACLAutoInherited  SecurityDescriptorControl = 0x0400
	SACLAutoInherited  SecurityDescriptorControl = 0x0800
	DACLProtected      SecurityDescriptorControl = 0x1000
	SACLProtected      SecurityDescriptorControl = 0x2000
	RmControlValid     SecurityDescriptorControl = 0x4000

	// SeSelfRelative is a boolean flag which, when set, indicates that the
	// security descriptor is in self-relative form.  In this form,
	// all fields of the security descriptor are contiguous in memory
	// and all pointer fields are expressed as offsets from the
	// beginning of the security descriptor.
	SelfRelative SecurityDescriptorControl = 0x8000
)

// HasFlag returns true if the security descriptor control contains the given
// flag, otherwise it returns false.
func (value SecurityDescriptorControl) HasFlag(flag SecurityDescriptorControl) bool {
	return value&flag == flag
}

type IdentifierAuthority [6]uint8

func (b IdentifierAuthority) Uint64() uint64 {
	return uint64(b[0])<<38 | uint64(b[1])<<30 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa379649

var (
	SecurityNullRelativeSID uint32 = 0
	SecurityWorldRid        uint32 = 1
)

var (
	nullIdentifierAuthority      = IdentifierAuthority{0, 0, 0, 0, 0, 0} // S-1-0
	worldIdentifierAuthority     = IdentifierAuthority{0, 0, 0, 0, 0, 1} // S-1-1
	localIdentifierAuthority     = IdentifierAuthority{0, 0, 0, 0, 0, 2} // S-1-2
	creatorIdentifierAuthority   = IdentifierAuthority{0, 0, 0, 0, 0, 3} // S-1-3
	nonUniqueIdentifierAuthority = IdentifierAuthority{0, 0, 0, 0, 0, 4} // S-1-4
	ntIdentifierAuthority        = IdentifierAuthority{0, 0, 0, 0, 0, 5} // S-1-5
)

// NullIdentifierAuthority represents SID S-1-0
func NullIdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 0}
}

// WorldIdentifierAuthority represents SID S-1-1
func WorldIdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 1}
}

// LocalIdentifierAuthority represents SID S-1-2
func LocalIdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 2}
}

// CreatorIdentifierAuthority represents SID S-1-3
func CreatorIdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 3}
}

// NonUniqueAuthority represents SID S-1-4
func NonUniqueAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 4}
}

// NTIdentifierAuthority represents SID S-1-5
func NTIdentifierAuthority() IdentifierAuthority {
	return IdentifierAuthority{0, 0, 0, 0, 0, 5}
}

// AcessControlType specifies the type of an access control entry and determines
// the data structure used to represent it
type AccessControlType uint8

const (
	// AccessAllowedControl specifies an access control entry granting access to
	// a particular trustee, which is in the form of a SID. It is only used in
	// Discretionary ACLs.
	//
	// A data structure of AccessAllowedAce represents this type of ACE.
	AccessAllowedControl AccessControlType = 0

	// AccessDeniedControl specifies an access control entry denying access to
	// a particular trustee, which is in the form of a SID. It is only used in
	// Discretionary ACLs.
	//
	// A data structure of AccessDeniedAce represents this type of ACE.
	AccessDeniedControl AccessControlType = 1

	// SystemAuditControl is not supported as it became obsolete as of Win2k
	SystemAuditControl AccessControlType = 2
	SystemAlarmControl AccessControlType = 3 /* Not implemented as of Win2k. */

	AccessAllowedCompoundControl AccessControlType = 4

	/* The following are Win2k only. */
	AccessAllowedObjectControl AccessControlType = 5
	AccessDeniedObjectControl  AccessControlType = 6
	SystemAuditObjectControl   AccessControlType = 7
	SystemAlarmObjectControl   AccessControlType = 8
	AccessMaxMsObjectControl   AccessControlType = 8
)

type AccessControlFlag uint8

// HasFlag returns true if the access control contains the given flag,
// otherwise it returns false.
func (value AccessControlFlag) HasFlag(flag AccessControlFlag) bool {
	return value&flag == flag
}

const (
	/* The inheritance flags. */
	ObjectInheritFlag      AccessControlFlag = 0x01
	ContainerInheritFlag   AccessControlFlag = 0x02
	NoPropagateInheritFlag AccessControlFlag = 0x04
	InheritOnlyFlag        AccessControlFlag = 0x08
	InheritedFlag          AccessControlFlag = 0x10 /* Win2k only. */
	ValidInheritanceFlags  AccessControlFlag = 0x1f

	/* The audit flags. */
	SuccessfulAccessFlag AccessControlFlag = 0x40
	FailedAccessFlag     AccessControlFlag = 0x80
)

type ObjectAccessControlFlag uint32

const (
	ObjectTypePresent          = 1
	InheritedObjectTypePresent = 2
)

type AccessMask uint32

const (
	// Specific rights indicated by bits 0 through 15 depend on the type of the
	// object being secured by the ACE.

	// FileReadData specifies the right to read data from a file. (FILE)
	FileReadData AccessMask = 0x00000001

	// FileListDirectory specifies the right to list the contents of a directory. (DIRECTORY)
	FileListDirectory AccessMask = 0x00000001

	// FileWriteData specifies the right to write data to a file. (FILE)
	FileWriteData AccessMask = 0x00000002

	// FileAddFile specifies the right to create a file in a directory. (DIRECTORY)
	FileAddFile AccessMask = 0x00000002

	// FileAppendData specifies the right to append data to a file. (FILE)
	FileAppendData AccessMask = 0x00000004

	// FileAddSubdirectory specifies the right to create a subdirectory. (DIRECTORY)
	FileAddSubdirectory AccessMask = 0x00000004

	// FileReadEA specifies the right to read extended attributes. (FILE/DIRECTORY)
	FileReadEA AccessMask = 0x00000008

	// FileWriteEA specifies the right to write extended attributes. (FILE/DIRECTORY)
	FileWriteEA AccessMask = 0x00000010

	// FileExecute specifies the right to execute a file. (FILE)
	FileExecute AccessMask = 0x00000020

	// FileTraverse specifies the right to traverse a directory. (DIRECTORY)
	FileTraverse AccessMask = 0x00000020

	// FileDeleteChild specifies the right to delete a directory and all the files
	// it contains (its children), even if the files are read-only. (DIRECTORY)
	FileDeleteChild AccessMask = 0x00000040

	// FileReadAttributes specifies the right to read file attributes. (FILE/DIRECTORY)
	FileReadAttributes AccessMask = 0x00000080

	// FileWriteAttributes specifies the right to change file attributes. (FILE/DIRECTORY)
	FileWriteAttributes AccessMask = 0x00000100

	// Standard rights indicated by bits 16 through 23 are independent of the type
	// of object being secured.

	// Delete specifies the right to delete an object.
	Delete AccessMask = 0x00010000

	// ReadControl specifies the right to read the information in an object's
	// security descriptor, not including the information in the SACL: i.e. the
	// right to read the security descriptor and owner.
	ReadControl AccessMask = 0x00020000

	// WriteDAC
	WriteDAC AccessMask = 0x00040000

	// WriteOwner
	WriteOwner AccessMask = 0x00080000

	// Synchronize
	Synchronize AccessMask = 0x00100000

	// The following standard rights are combinations of the above for
	// convenience and are defined by the Win32 API.

	// StandardRightsRead
	StandardRightsRead = 0x00020000

	// StandardRightsWrite
	StandardRightsWrite = 0x00020000

	// StandardRightsExecute
	StandardRightsExecute AccessMask = 0x00020000

	// StandardRightsRequired
	StandardRightsRequired AccessMask = 0x000f0000

	// StandardRightsAll
	StandardRightsAll AccessMask = 0x001f0000

	// The access system ACL and maximum allowed access types are indicated by
	// bits 24 through 25

	// AccessSystemSecurity
	AccessSystemSecurity AccessMask = 0x01000000

	// MaximumAllowed
	MaximumAllowed AccessMask = 0x02000000

	// Bits 26 to 27 are reserved

	// Generic rights are indicated by bits 28 through 31 and map onto the
	// standard and specific rights

	// GenericAll
	GenericAll AccessMask = 0x10000000

	// GenericExecute
	GenericExecute AccessMask = 0x20000000

	// GenericWrite
	GenericWrite AccessMask = 0x40000000

	// GenericRead
	GenericRead AccessMask = 0x80000000
)

type GUID [16]byte // TODO: Decide whether we really should roll our own GUID type

// See: http://en.wikipedia.org/wiki/Universally_unique_identifier

func (g GUID) String() string {
	output := ""
	output += hex.EncodeToString(g[0:4])
	output += "-"
	output += hex.EncodeToString(g[4:6])
	output += "-"
	output += hex.EncodeToString(g[6:8])
	output += "-"
	output += hex.EncodeToString(g[8:10])
	output += "-"
	output += hex.EncodeToString(g[10:16])
	return output
}
