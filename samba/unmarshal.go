package samba

import (
	"errors"

	"go.scj.io/samba-over-ntfs/ntsecurity"
)

// UnmarshalBinary reads a security descriptor from a byte slice containing
// system.NTACL attribute data formatted according to a Samba NDR data layout.
func (sd *SecurityDescriptor) UnmarshalBinary(data []byte) (err error) {
	attr := NativeXAttr(data)
	//fmt.Printf("%d %d %x %d\n", n.Version(), n.VersionNDR(), b[4:8], n.SecurityDescriptorOffset())
	if !attr.Valid() {
		return errors.New("Invalid Samba XAttr Security Descriptor Data")
	}

	sd.Version = attr.Version()
	present := attr.ContainsSecurityDescriptor()
	offset := attr.SecurityDescriptorOffset()

	if present {
		switch sd.Version {
		case 4:
			n := NativeSecurityDescriptorHashV4(data[offset:])
			present = n.ContainsSecurityDescriptor()
			offset += n.SecurityDescriptorOffset()
		case 3:
			n := NativeSecurityDescriptorHashV3(data[offset:])
			present = n.ContainsSecurityDescriptor()
			offset += n.SecurityDescriptorOffset()
		case 2:
			n := NativeSecurityDescriptorHashV2(data[offset:])
			present = n.ContainsSecurityDescriptor()
			offset += n.SecurityDescriptorOffset()
		case 1:
			n := NativeSecurityDescriptorHashV1(data[offset:])
			offset += n.SecurityDescriptorOffset()
		default:
			return errors.New("Unknown Samba XAttr NTACL Version")
		}
	}

	if !present {
		// TODO: Decide whether this should be an error
		if sd.SecurityDescriptor != nil {
			*sd.SecurityDescriptor = ntsecurity.SecurityDescriptor{} // Is this appropriate?
		}
		return
	}

	if sd.SecurityDescriptor == nil {
		sd.SecurityDescriptor = new(ntsecurity.SecurityDescriptor)
	}

	sd.SecurityDescriptor.UnmarshalBinaryOffset(data, offset)
	return
}
