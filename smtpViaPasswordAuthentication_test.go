package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func TestSmtpAuthenticateViaPassword(t *testing.T) {
	makeDefaultAuthFile()

	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaPasswordAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Enabled())

	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", fakePasswords[0].pass))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", fakePasswords[1].pass))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user2", fakePasswords[0].pass))
	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaPasswordAuthentication().Authenticate("user2", fakePasswords[1].pass))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user3", fakePasswords[1].pass))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user5", fakePasswords[0].pass))
}

func TestSmtpAuthenticateViaPasswordSetPassword(t *testing.T) {
	makeDefaultAuthFile()

	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaPasswordAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", fakePasswords[1].pass))
	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", "foo_bar"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaPasswordAuthentication().SetPassword("user1", "foo_bar"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", fakePasswords[1].pass))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaPasswordAuthentication().Authenticate("user1", "foo_bar"))
}
