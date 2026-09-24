//go:build windows

package licensing

import (
	"strings"

	"golang.org/x/sys/windows"
)

func privateSIDs() ([]*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{user.User.Sid, system, admins}, nil
}

func securePrivatePath(path string) error {
	sids, err := privateSIDs()
	if err != nil {
		return err
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func privatePathIsSecure(path string) (bool, error) {
	allowed, err := privateSIDs()
	if err != nil {
		return false, err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	sddl := descriptor.String()
	if !strings.Contains(sddl, "D:P") {
		return false, nil
	}
	for _, broad := range []string{";;;WD)", ";;;BU)", ";;;AU)", ";;;AN)", ";;;BG)"} {
		if strings.Contains(sddl, broad) {
			return false, nil
		}
	}
	for _, sid := range allowed {
		value := sid.String()
		present := strings.Contains(sddl, ";;;"+value+")")
		if sid.IsWellKnown(windows.WinLocalSystemSid) {
			present = present || strings.Contains(sddl, ";;;SY)")
		}
		if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			present = present || strings.Contains(sddl, ";;;BA)")
		}
		if !present {
			return false, nil
		}
	}
	return true, nil
}
