package authenticationFile

import (
	"errors"
	"github.com/mailhedgehog/contracts"
	"golang.org/x/crypto/bcrypt"
)

type dashboardViaPasswordAuthentication struct {
}

func (authentication *dashboardViaPasswordAuthentication) Enabled() bool {
	return fileAuthentication.config.Dashboard.ViaPasswordAuthentication.Enabled
}

func (authentication *dashboardViaPasswordAuthentication) Authenticate(username string, password string) bool {
	if !authentication.Enabled() {
		return true
	}

	user, ok := fileAuthentication.users[username]
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

	fileAuthentication.initUsers()

	var newPassHash []byte
	if len(password) > 0 {
		var err error
		newPassHash, err = contracts.CreatePasswordHash(password)
		if err != nil {
			return err
		}
	}

	fileAuthentication.users[username] = userInfo{
		username:      username,
		dashboardPass: string(newPassHash),
	}

	return fileAuthentication.writeToFile()
}
