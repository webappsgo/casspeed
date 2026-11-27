package server

import (
	"strings"
	"testing"
)

func TestAdminDestructivePagesRequireConfirmationPopovers(t *testing.T) {
	pages := map[string]string{
		"roles": executeTemplate(rolesTemplate, map[string]any{
			"Path": "/server/admin/roles", "CSRF": "csrf", "Roles": []roleRow{{Name: "support", CanDelete: true, PermissionsText: "read"}},
			"Permissions": []rolePermissionOption{}, "CreateTitle": "Create", "CreateButton": "Create", "SaveButton": "Save",
			"NameLabel": "Name", "PermissionsLabel": "Permissions", "ActionsLabel": "Actions", "DeleteButton": "Delete role",
			"ProtectedLabel": "Protected", "Empty": "No roles", "Cancel": "Cancel", "Confirm": "Confirm",
		}),
		"users": executeTemplate(userAdminTemplate, map[string]any{
			"Path": "/server/admin/users", "InvitesURL": "/server/admin/users/invites", "SearchLabel": "Search", "SearchButton": "Search",
			"CreateTitle": "Create", "UsernameLabel": "Username", "EmailLabel": "Email", "CreateInvite": "Invite", "CreateDirect": "Create",
			"Users": []userAdminRow{{ID: 4, Username: "reader", Status: "Active", CreatedAt: "today", Action: "disable", ActionLabel: "Suspend", ConfirmAction: true}},
			"CSRF":  "csrf", "IDLabel": "ID", "StatusLabel": "Status", "CreatedLabel": "Created", "ActionsLabel": "Actions",
			"Cancel": "Cancel", "Confirm": "Confirm", "RevokeSessions": "Revoke sessions", "Details": "Details", "NoUsers": "No users",
			"PageNav": "Pages", "PreviousLabel": "Previous", "NextLabel": "Next",
		}),
		"user detail": executeTemplate(userAdminDetailTemplate, map[string]any{
			"Path": "/server/admin/users", "ID": int64(4), "CSRF": "csrf", "Username": "reader", "Email": "r***@example.test",
			"Status": "Active", "TOTP": "No", "LastLogin": "Never", "Action": "disable", "ActionLabel": "Suspend", "ConfirmAction": true,
			"UsernameLabel": "Username", "EmailLabel": "Email", "StatusLabel": "Status", "TwoFactorLabel": "Two-factor", "LastLoginLabel": "Last login",
			"Cancel": "Cancel", "Confirm": "Confirm", "RevokeSessions": "Revoke sessions", "DeleteUser": "Delete user", "DeleteWarning": "This is permanent.",
			"UsernameConfirmation": "Type the username", "Back": "Back",
		}),
		"invites": executeTemplate(userInvitesTemplate, map[string]any{
			"Path": "/server/admin/users/invites", "BackURL": "/server/admin/users", "CSRF": "csrf", "Invites": []userInviteRow{{ID: 7, Role: "user", UseCount: 0, MaxUses: "1", ExpiresAt: "tomorrow"}},
			"ExpiryDefault": "tomorrow", "GenerateTitle": "Generate", "RoleLabel": "Role", "Roles": []userRoleOption{}, "ExpiryLabel": "Expires",
			"ExpiryUTC": "UTC", "MaxUsesLabel": "Max uses", "UnlimitedHint": "Zero is unlimited", "GenerateInvite": "Generate invite",
			"InviteListTitle": "Invites", "UsesLabel": "Uses", "ActionsLabel": "Actions", "RevokeLabel": "Revoke", "Cancel": "Cancel",
			"Confirm": "Confirm", "NoInvites": "No invites", "Back": "Back",
		}),
	}
	for name, page := range pages {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(page, "popover") || !strings.Contains(page, `type="button" popovertarget=`) || !strings.Contains(page, `type="submit">Confirm</button>`) {
				t.Fatalf("destructive action lacks a confirmation popover: %s", page)
			}
		})
	}
}
