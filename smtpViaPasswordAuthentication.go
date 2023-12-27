package authenticationFile

import (
	"errors"
	"github.com/mailhedgehog/contracts"
	"golang.org/x/crypto/bcrypt"
)

type smtpViaPasswordAuthentication struct {
	context *storageContext
}

func (authentication *smtpViaPasswordAuthentication) Enabled() bool {
	return authentication.context.config.Smtp.ViaPasswordAuthentication.Enabled
}

func (authentication *smtpViaPasswordAuthentication) Authenticate(username string, password string) bool {
	if !authentication.Enabled() {
		return true
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.smtpPass), []byte(password)); err != nil {
		return false
	}

	return true
}

func (authentication *smtpViaPasswordAuthentication) SetPassword(username string, password string) error {
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
		username: username,
		smtpPass: string(newPassHash),
	}

	return authentication.context.storage.writeToFile()
}
