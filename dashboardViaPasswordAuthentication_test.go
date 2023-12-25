package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func init() {
	makeDefaultAuthFile()
}

func TestDashboardAuthenticateViaPassword(t *testing.T) {
	config := &contracts.AuthenticationConfig{}
	config.Dashboard.ViaPasswordAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.Dashboard().ViaPasswordAuthentication().Enabled())

	(*gounit.T)(t).AssertTrue(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user1", fakePasswords[0].pass))
	(*gounit.T)(t).AssertTrue(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user2", fakePasswords[0].pass))
	(*gounit.T)(t).AssertFalse(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user2", fakePasswords[1].pass))
	(*gounit.T)(t).AssertFalse(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user3", fakePasswords[1].pass))
	(*gounit.T)(t).AssertFalse(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user3", ""))
	(*gounit.T)(t).AssertTrue(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user5", fakePasswords[0].pass))
}
