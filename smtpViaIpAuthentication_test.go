package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func init() {
	makeDefaultAuthFile()
}

func TestViaIpAuthenticationReturnsFalseIfEmptyList(t *testing.T) {
	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaIpAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Enabled())

	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))
}

func TestViaIpAuthenticationAddIp(t *testing.T) {
	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaIpAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.3"))
}

func TestViaIpAuthenticationDeleteIp(t *testing.T) {
	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaIpAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// No error if empty list
	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().DeleteIp("user1", "1.1.1.1"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().DeleteIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))
}

func TestViaIpAuthenticationClearAllIps(t *testing.T) {
	config := &contracts.AuthenticationConfig{}
	config.Smtp.ViaIpAuthentication.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// No error if empty list
	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().ClearAllIps("user1"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().ViaIpAuthentication().ClearAllIps("user1"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().ViaIpAuthentication().Authenticate("user1", "1.1.1.2"))
}
