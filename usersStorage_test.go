package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"testing"
)

func TestUsersStorageExists(t *testing.T) {
	makeDefaultAuthFile()
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, &contracts.AuthenticationConfig{})
	(*gounit.T)(t).AssertEqualsInt(4, len(auth.users))

	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user1"))
	(*gounit.T)(t).AssertFalse(auth.UsersStorage().Exists("user0"))
	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user2"))
}

func TestUsersStorageAdd(t *testing.T) {
	makeDefaultAuthFile()
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, &contracts.AuthenticationConfig{})
	(*gounit.T)(t).AssertEqualsInt(4, len(auth.users))

	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user1"))

	(*gounit.T)(t).AssertNotError(auth.UsersStorage().Add("user1"))
	(*gounit.T)(t).AssertEqualsInt(4, len(auth.users))
	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user1"))

	(*gounit.T)(t).AssertNotError(auth.UsersStorage().Add("user0"))
	(*gounit.T)(t).AssertEqualsInt(5, len(auth.users))
	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user0"))
}

func TestUsersStorageDelete(t *testing.T) {
	makeDefaultAuthFile()
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, &contracts.AuthenticationConfig{})
	(*gounit.T)(t).AssertEqualsInt(4, len(auth.users))

	(*gounit.T)(t).AssertTrue(auth.UsersStorage().Exists("user1"))

	(*gounit.T)(t).AssertNotError(auth.UsersStorage().Delete("user1"))
	(*gounit.T)(t).AssertEqualsInt(3, len(auth.users))
	(*gounit.T)(t).AssertFalse(auth.UsersStorage().Exists("user1"))
}

func TestUsersStorageList(t *testing.T) {
	makeDefaultAuthFile()
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, &contracts.AuthenticationConfig{})

	list, foundCount, err := auth.UsersStorage().List("er2", 0, 100)

	(*gounit.T)(t).AssertNotError(err)
	(*gounit.T)(t).AssertEqualsInt(1, foundCount)
	(*gounit.T)(t).AssertEqualsString("user2", list[0].Username)
}
