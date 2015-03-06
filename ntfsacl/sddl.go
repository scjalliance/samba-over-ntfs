package ntfsacl

import "fmt"

const (
	sddlOwnerTag = "O"
	sddlGroupTag = "G"
	sddlDACLTag  = "D"
	sddlSACLTag  = "S"
)

// SDDL returns a string representation of the security identifier in the format
// expected by the security descriptor definition language.
func (sd SecurityDescriptor) SDDL() string {
	output := ""
	if sd.Owner != nil {
		output += sddlOwnerTag + ":" + sd.Owner.SDDL()
	}
	if sd.Group != nil {
		output += sddlGroupTag + ":" + sd.Group.SDDL()
	}
	if sd.Control.HasFlag(DACLPresent) {
		output += sddlDACLTag + ":"
		if sd.DACL != nil {
			// TODO: Handle the relevant DACL control flags
			output += sd.DACL.SDDL()
		}
	}
	if sd.Control.HasFlag(SACLPresent) {
		output += sddlSACLTag + ":"
		if sd.SACL != nil {
			// TODO: Handle the relevant SACL control flags
			output += sd.SACL.SDDL()
		}
	}
	return output
}

// SDDL returns a string representation of the access control list in the format
// expected by the security descriptor definition language.
func (acl ACL) SDDL() string {
	output := ""
	for _, entry := range acl.Entries {
		output += entry.SDDL()
	}
	return output
}

// SDDL returns a string representation of the access control entry in the
// format expected by the security descriptor definition language.
func (ace ACE) SDDL() string {
	// TODO: Write this function
	return ""
}

// See: https://msdn.microsoft.com/en-us/library/aa379602

const (
	sddlAnonymousTag                   = "AN" // Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
	sddlAccountOperatorsTag            = "AO" // Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
	sddlAuthenticatedUsersTag          = "AU" // Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
	sddlBuiltinAdministratorsTag       = "BA" // Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
	sddlBuiltinGuestsTag               = "BG" // Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
	sddlBackupOperatorsTag             = "BO" // Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
	sddlBuiltinUsersTag                = "BU" // Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
	sddlCertServAdministratorsTag      = "CA" // Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
	sddlCertsvcDcomAccessTag           = "CD" // Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
	sddlCreatorGroupTag                = "CG" // Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
	sddlCreatorOwnerTag                = "CO" // Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
	sddlDomainAdministratorsTag        = "DA" // Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
	sddlDomainComputersTag             = "DC" // Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
	sddlDomainDomainControllersTag     = "DD" // Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
	sddlDomainGuestsTag                = "DG" // Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
	sddlDomainUsersTag                 = "DU" // Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
	sddlEnterpriseAdminsTag            = "EA" // Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
	sddlEnterpriseDomainControllersTag = "ED" // Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
	sddlMlHighTag                      = "HI" // High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
	sddlInteractiveTag                 = "IU" // Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
	sddlLocalAdminTag                  = "LA" // Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
	sddlLocalGuestTag                  = "LG" // Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
	sddlLocalServiceTag                = "LS" // Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
	sddlMlLowTag                       = "LW" // Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
	sddlMlMediumTag                    = "ME" // Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
	sddlPerfmonUsersTag                = "MU" // Performance Monitor users.
	sddlNetworkConfigurationOpsTag     = "NO" // Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
	sddlNetworkServiceTag              = "NS" // Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
	sddlNetworkTag                     = "NU" // Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
	sddlGroupPolicyAdminsTag           = "PA" // Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
	sddlPrinterOperatorsTag            = "PO" // Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
	sddlPersonalSelfTag                = "PS" // Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
	sddlPowerUsersTag                  = "PU" // Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
	sddlRestrictedCodeTag              = "RC" // Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
	sddlRemoteDesktopTag               = "RD" // Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
	sddlReplicatorTag                  = "RE" // Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
	sddlEnterpriseRoDcsTag             = "RO" // Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
	sddlRasServersTag                  = "RS" // RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
	sddlAliasPrew2kcompaccTag          = "RU" // Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
	sddlSchemaAdministratorsTag        = "SA" // Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
	sddlMlSystemTag                    = "SI" // System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
	sddlServerOperatorsTag             = "SO" // Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
	sddlServiceTag                     = "SU" // Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
	sddlLocalSystemTag                 = "SY" // Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
	sddlEveryoneTag                    = "WD" // Everyone. The corresponding RID is SecurityWorldRid.
)

// SDDL returns a string representation of the security identifier in the format
// expected by the security descriptor definition language. Well known values
// will be represented by a two letter abbreviation while all other values will
// be represented in the standard S-R-I-S notation.
func (sid SID) SDDL() string {
	// TODO: Return constants for all well known values
	if sid.Revision == 1 && sid.SubAuthorityCount > 0 {
		switch sid.IdentifierAuthority {
		case worldIdentifierAuthority:
			switch sid.SubAuthority[0] {
			case SecurityWorldRid:
				return sddlEveryoneTag
			}
		}
	}
	return fmt.Sprint(sid)
}

const (
	sddlAccessAllowedTag         = "A"
	sddlAccessDeniedTag          = "D"
	sddlSystemAuditTag           = "AU"
	sddlSystemAlarmTag           = "AL"
	sddlAccessAllowedCompoundTag = "" // FIXME: Figure out if this has a value
	sddlAccessAllowedObjectTag   = "OA"
	sddlAccessDeniedObjectTag    = "OD"
	sddlSystemAuditObjectTag     = "OU"
	sddlSystemAlarmObjectTag     = "AL"
)

// SDDL returns a string representation of the access control entry type in the
// format expected by the security descriptor definition language.
func (t AccessControlType) SDDL() string {
	switch t {
	case AccessAllowedControl:
		return sddlAccessAllowedTag
	case AccessDeniedControl:
		return sddlAccessDeniedTag
	case SystemAuditControl:
		return sddlSystemAuditTag
	case SystemAlarmControl:
		return sddlSystemAlarmTag
	case AccessAllowedObjectControl:
		return sddlAccessAllowedObjectTag
	case AccessDeniedObjectControl:
		return sddlAccessDeniedObjectTag
	case SystemAuditObjectControl:
		return sddlSystemAuditObjectTag
	case SystemAlarmObjectControl:
		return sddlSystemAlarmObjectTag
	default:
		return ""
	}
}

const (
	sddlObjectInheritTag      = "OI"
	sddlContainerInheritTag   = "CI"
	sddlNoPropagateInheritTag = "NP"
	sddlInheritOnlyTag        = "IO"
	sddlInheritedTag          = "ID"
	sddlSuccessfulAccessTag   = "SA"
	sddlFailedAccessTag       = "FA"
)

// SDDL returns a string representation of the access control entry flags in the
// format expected by the security descriptor definition language.
func (f AccessControlFlag) SDDL() string {
	s := ""
	if f.HasFlag(ObjectInheritFlag) {
		s += sddlObjectInheritTag
	}
	if f.HasFlag(ContainerInheritFlag) {
		s += sddlContainerInheritTag
	}
	if f.HasFlag(NoPropagateInheritFlag) {
		s += sddlNoPropagateInheritTag
	}
	if f.HasFlag(InheritOnlyFlag) {
		s += sddlInheritOnlyTag
	}
	if f.HasFlag(InheritedFlag) {
		s += sddlInheritedTag
	}
	if f.HasFlag(SuccessfulAccessFlag) {
		s += sddlSuccessfulAccessTag
	}
	if f.HasFlag(FailedAccessFlag) {
		s += sddlFailedAccessTag
	}
	return s
}
