package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func TestViaEmailAuthenticationSendToken(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaEmailAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// TODO: not implemented
	(*gounit.T)(t).ExpectError(auth.Dashboard().ViaEmailAuthentication().SendToken("user1", "test@test.com"))
}

func TestViaEmailAuthenticationAuthenticate(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaEmailAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// TODO: not implemented
	(*gounit.T)(t).AssertFalse(auth.Dashboard().ViaEmailAuthentication().Authenticate("user1", "test@test.com", "123"))
}

func TestViaEmailAuthenticationAddEmail(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaEmailAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.Dashboard().ViaEmailAuthentication().Enabled())

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test@test.com"))
	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test2@test.com"))

	(*gounit.T)(t).AssertEqualsInt(2, len(auth.users["user1"].dashboardAuthEmails))
	(*gounit.T)(t).AssertEqualsString("test2@test.com", auth.users["user1"].dashboardAuthEmails[1])
}

func TestViaEmailAuthenticationDeleteEmail(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaEmailAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().DeleteEmail("user1", "foo@test.com"))

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test@test.com"))
	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test2@test.com"))

	(*gounit.T)(t).AssertEqualsInt(2, len(auth.users["user1"].dashboardAuthEmails))

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().DeleteEmail("user1", "test2@test.com"))

	(*gounit.T)(t).AssertEqualsInt(1, len(auth.users["user1"].dashboardAuthEmails))
	(*gounit.T)(t).AssertEqualsString("test@test.com", auth.users["user1"].dashboardAuthEmails[0])
}

func TestViaEmailAuthenticationClearAllEmails(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaEmailAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().ClearAllEmails("user1"))

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test@test.com"))
	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().AddEmail("user1", "test2@test.com"))

	(*gounit.T)(t).AssertEqualsInt(2, len(auth.users["user1"].dashboardAuthEmails))

	(*gounit.T)(t).AssertNotError(auth.Dashboard().ViaEmailAuthentication().ClearAllEmails("user1"))

	(*gounit.T)(t).AssertEqualsInt(0, len(auth.users["user1"].dashboardAuthEmails))
}
