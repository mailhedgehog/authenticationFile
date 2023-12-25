package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func TestSmtpCheckAllowlistReturnsFalseIfEmpty(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Smtp.IpsAllowList.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Enabled())

	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "1.2.3.4"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user2", "1.2.3.4"))
}

func TestSmtpAddIp(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Smtp.IpsAllowList.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.2.3.4"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user2", "1.2.3.4"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user2", "2.2.3.4"))
	// Duplication not returns error
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user2", "2.2.3.4"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.2.3.4"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user2", "1.2.3.4"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "2.2.3.4"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user2", "2.2.3.4"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "3.2.3.4"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user2", "3.2.3.4"))
}

func TestSmtpDeleteIp(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Smtp.IpsAllowList.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// Delete not existing not returns error
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().DeleteIp("user1", "1.1.1.1"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().DeleteIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.2"))

}

func TestSmtpClearAllIps(t *testing.T) {
	makeDefaultAuthFile()
	config := &contracts.AuthenticationConfig{}
	config.Smtp.IpsAllowList.Enabled = true
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

	// Delete not existing not returns error
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().DeleteIp("user1", "1.1.1.1"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().ClearAllIps("user1"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertNotError(auth.SMTP().IpsAllowList().AddIp("user1", "1.1.1.2"))

	(*gounit.T)(t).AssertFalse(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.1"))
	(*gounit.T)(t).AssertTrue(auth.SMTP().IpsAllowList().Allowed("user1", "1.1.1.2"))
}
