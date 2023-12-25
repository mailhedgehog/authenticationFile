package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/gounit"
	"github.com/mailhedgehog/logger"
	"os"
	"testing"
)

var filePath = ""

type fakePassword struct {
	pass string
	hash string
}

var fakePasswords = []fakePassword{
	{
		pass: "test1",
		hash: "$2a$12$CV3q6WzQBGEPqrPkh.hYn.HFO6mAxKfLLNxAMWIKx9wF93X6539nS",
	},
	{
		pass: "test2",
		hash: "$2a$12$6aBv1ox1kgMBcS9st4ixdu6HKW77DNdpyJNENN5vVMFqHHcF.q5Ra",
	},
}

func makeDefaultAuthFile() {
	dir, err := os.MkdirTemp("", "mailhedgehog_")
	logger.PanicIfError(err)

	filePath = dir + string(os.PathSeparator) + ".mh-authfile"
	file, err := os.Create(filePath)
	logger.PanicIfError(err)

	fileLines := [][]byte{
		[]byte("user1:" + fakePasswords[0].hash + ":" + fakePasswords[1].hash + "\n"),
		[]byte("user2:" + fakePasswords[0].hash + "\n"),
		[]byte("user3::" + fakePasswords[1].hash + "\n"),
		[]byte(":::\n"),    // not passed
		[]byte(":user4\n"), // not passed
		[]byte("user5:" + fakePasswords[0].hash + ":\n"),
	}
	for _, line := range fileLines {
		_, err = file.Write(line)
		logger.PanicIfError(err)
	}
	file.Sync()
	file.Close()

	file, err = os.Create(filePath + "2")
	logger.PanicIfError(err)
	file.Close()
}

func TestAuthFile(t *testing.T) {
	makeDefaultAuthFile()
	auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, &contracts.AuthenticationConfig{})
	(*gounit.T)(t).AssertEqualsInt(4, len(auth.users))

	auth = CreateFileAuthentication(&StorageConfiguration{Path: filePath + "2"}, &contracts.AuthenticationConfig{})
	(*gounit.T)(t).AssertLessOrEqualInt(len(auth.users), 0)
}
