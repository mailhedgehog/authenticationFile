package authenticationFile

import (
	"errors"
	"github.com/mailhedgehog/contracts"
	"golang.org/x/crypto/bcrypt"
)

type dashboardViaPasswordAuthentication struct {
	context *storageContext
}

func (authentication *dashboardViaPasswordAuthentication) Enabled() bool {
	return authentication.context.config.Dashboard.ViaPasswordAuthentication.Enabled
}

func (authentication *dashboardViaPasswordAuthentication) Authenticate(username string, password string) bool {
	if !authentication.Enabled() {
		return true
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.dashboardPass), []byte(password)); err != nil {
		return false
	}

	return true
}

func (authentication *dashboardViaPasswordAuthentication) SetPassword(username string, password string) error {
	if len(username) <= 0 {
		return errors.New("username required")
	}

	authentication.context.storage.initUsers()

	var newPassHash []byte
	if len(password) > 0 {
		var err error
		newPassHash, err = contracts.CreatePasswordHash(password)
		if err != nil {
			return err
		}
	}

	authentication.context.storage.users[username] = userInfo{
		username:      username,
		dashboardPass: string(newPassHash),
	}

	return authentication.context.storage.writeToFile()
}
