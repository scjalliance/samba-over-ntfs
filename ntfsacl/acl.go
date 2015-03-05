package ntfsacl

import "fmt"

type SecurityDescriptor struct {
	Revision  uint8
	Alignment uint8
	Control   SecurityDescriptorControl
	Owner     *SID
	Group     *SID
	Sacl      *ACL
	Dacl      *ACL
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
	IdentifierAuthority SidIdentifierAuthority
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
	output += fmt.Sprint(sid.IdentifierAuthority)
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
	AclMinRevision = 2
	AclMaxRevision = 4
)

// An ACE is an access-control entry in an access-control list (ACL).
// An ACE defines access to an object for a specific user or group or defines
// the types of access that generate system-administration messages or alarms
// for a specific user or group. The user or group is identified by a security
// identifier (SID).
type ACE struct {
	Type                AceType
	Flags               AceFlag
	Mask                AccessMask
	Sid                 SID
	ObjectFlags         ObjectAceFlag
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
	SeOwnerDefaulted SecurityDescriptorControl = 0x0001

	// SeGroupDefaulted is a boolean flag which, when set, indicates that the
	// SID in the Group field was provided by a defaulting mechanism
	// rather than explicitly provided by the original provider of
	// the security descriptor.  This may affect the treatment of
	// the SID with respect to inheritance of a primary group.
	SeGroupDefaulted SecurityDescriptorControl = 0x0002

	// SeDaclPresent is a boolean flag which, when set, indicates that the
	// security descriptor contains a discretionary ACL. If this
	// flag is set and the Dacl field of the SECURITY_DESCRIPTOR is
	// null, then a null ACL is explicitly being specified.
	SeDaclPresent SecurityDescriptorControl = 0x0004

	// SeDaclDefaulted is a boolean flag which, when set, indicates that the
	// ACL pointed to by the Dacl field was provided by a defaulting
	// mechanism rather than explicitly provided by the original
	// provider of the security descriptor. This may affect the
	// treatment of the ACL with respect to inheritance of an ACL.
	// This flag is ignored if the DaclPresent flag is not set.
	SeDaclDefaulted SecurityDescriptorControl = 0x0008

	// SeSaclPresent is a boolean flag which, when set, indicates that the
	// security descriptor contains a system ACL pointed to by the
	// Sacl field. If this flag is set and the Sacl field of the
	// SECURITY_DESCRIPTOR is null, then an empty (but present)
	// ACL is being specified.
	SeSaclPresent SecurityDescriptorControl = 0x0010

	// SeSaclDefaulted is a boolean flag which, when set, indicates that the
	// ACL pointed to by the Sacl field was provided by a defaulting
	// mechanism rather than explicitly provided by the original
	// provider of the security descriptor. This may affect the
	// treatment of the ACL with respect to inheritance of an ACL.
	// This flag is ignored if the SaclPresent flag is not set.
	SeSaclDefaulted SecurityDescriptorControl = 0x0020

	SeDaclAutoInheritReq SecurityDescriptorControl = 0x0100
	SeSaclAutoInheritReq SecurityDescriptorControl = 0x0200
	SeDaclAutoInherited  SecurityDescriptorControl = 0x0400
	SeSaclAutoInherited  SecurityDescriptorControl = 0x0800
	SeDaclProtected      SecurityDescriptorControl = 0x1000
	SeSaclProtected      SecurityDescriptorControl = 0x2000
	SeRmControlValid     SecurityDescriptorControl = 0x4000

	// SeSelfRelative is a boolean flag which, when set, indicates that the
	// security descriptor is in self-relative form.  In this form,
	// all fields of the security descriptor are contiguous in memory
	// and all pointer fields are expressed as offsets from the
	// beginning of the security descriptor.
	SeSelfRelative SecurityDescriptorControl = 0x8000
)

func (control SecurityDescriptorControl) HasFlag(flag SecurityDescriptorControl) bool {
	return control|flag == control
}

type SidIdentifierAuthority [8]uint8

// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa379649

var (
	SecurityNullRelativeSID uint32 = 0
	SecurityWorldRid        uint32 = 1
)

var (
	securityNullSidAuthority    = SidIdentifierAuthority{0, 0, 0, 0, 0, 0} // S-1-0
	securityWorldSidAuthority   = SidIdentifierAuthority{0, 0, 0, 0, 0, 1} // S-1-1
	securityLocalSidAuthority   = SidIdentifierAuthority{0, 0, 0, 0, 0, 2} // S-1-2
	securityCreatorSidAuthority = SidIdentifierAuthority{0, 0, 0, 0, 0, 3} // S-1-3
	securityNonUniqueAuthority  = SidIdentifierAuthority{0, 0, 0, 0, 0, 4} // S-1-4
	securityNtSidAuthority      = SidIdentifierAuthority{0, 0, 0, 0, 0, 5} // S-1-5
)

// SecurityNullSidAuthority represents SID S-1-0
func SecurityNullSidAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 0}
}

// SecurityWorldSidAuthority represents SID S-1-1
func SecurityWorldSidAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 1}
}

// SecurityLocalSidAuthority represents SID S-1-2
func SecurityLocalSidAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 2}
}

// SecurityCreatorSidAuthority represents SID S-1-3
func SecurityCreatorSidAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 3}
}

// SecurityNonUniqueAuthority represents SID S-1-4
func SecurityNonUniqueAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 4}
}

// SecurityNtSidAuthority represents SID S-1-5
func SecurityNtSidAuthority() SidIdentifierAuthority {
	return SidIdentifierAuthority{0, 0, 0, 0, 0, 5}
}

// AceType specifies the type of an access control entry and determines the data
// structure used to represent it
type AceType uint8

const (
	// FIXME: These constants are a mess and need to be cleaned up somehow

	AccessMinMsAceType AceType = 0

	// AccessAllowedAceType specifies an access control entry granting access to
	// a particular trustee, which is in the form of a SID. It is only used in
	// Discretionary ACLs.
	//
	// A data structure of AccessAllowedAce represents this type of ACE.
	AccessAllowedAceType AceType = 0

	// AccessDeniedAceType specifies an access control entry denying access to
	// a particular trustee, which is in the form of a SID. It is only used in
	// Discretionary ACLs.
	//
	// A data structure of AccessDeniedAce represents this type of ACE.
	AccessDeniedAceType AceType = 1

	// SystemAuditAceType is not supported as it became obsolete as of Win2k
	SystemAuditAceType   AceType = 2
	SystemAlarmAceType   AceType = 3 /* Not implemented as of Win2k. */
	AccessMaxMsV2AceType AceType = 3

	AccessAllowedCompoundAceType AceType = 4
	AccessMaxMsV3AceType         AceType = 4

	/* The following are Win2k only. */
	AccessMinMsObjectAceType   AceType = 5
	AccessAllowedObjectAceType AceType = 5
	AccessDeniedObjectAceType  AceType = 6
	SystemAuditObjectAceType   AceType = 7
	SystemAlarmObjectAceType   AceType = 8
	AccessMaxMsObjectAceType   AceType = 8

	AccessMaxMsV4AceType AceType = 8

	/* This one is for WinNT&2k. */
	AccessMaxMsAceType = 8
)

type AceFlag uint8

const (
	/* The inheritance flags. */
	ObjectInheritAceFlag      AceFlag = 0x01
	ContainerInheritAceFlag   AceFlag = 0x02
	NoPropagateInheritAceFlag AceFlag = 0x04
	InheritOnlyAceFlag        AceFlag = 0x08
	InheritedAceFlag          AceFlag = 0x10 /* Win2k only. */
	ValidInheritAceFlags      AceFlag = 0x1f

	/* The audit flags. */
	SuccessfulAccessAceFlag AceFlag = 0x40
	FailedAccessAceFlag     AceFlag = 0x80
)

type ObjectAceFlag uint32

const (
	AceObjectTypePresent          = 1
	AceInheritedObjectTypePresent = 2
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
