package authenticationFile

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
)

type dashboardViaEmailAuthentication struct {
	context *storageContext
}

func (authentication *dashboardViaEmailAuthentication) Enabled() bool {
	return authentication.context.config.Dashboard.ViaEmailAuthentication.Enabled
}

func (authentication *dashboardViaEmailAuthentication) SendToken(username string, email string) error {
	return errors.New("functionality not implemented. please request developer to implement")
}

func (authentication *dashboardViaEmailAuthentication) Authenticate(username string, email string, token string) bool {
	return false
}

func (authentication *dashboardViaEmailAuthentication) AddEmail(username string, email string) error {
	if len(username) <= 0 || len(email) <= 0 {
		return errors.New("username and email required")
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.dashboardAuthEmails, email) {
		return nil
	}

	user.dashboardAuthEmails = append(user.dashboardAuthEmails, email)
	authentication.context.storage.users[username] = user

	return authentication.context.storage.writeToFile()
}

func (authentication *dashboardViaEmailAuthentication) DeleteEmail(username string, email string) error {
	if len(username) <= 0 || len(email) <= 0 {
		return errors.New("username and email required")
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.dashboardAuthEmails, email) {
		i := slices.Index(user.dashboardAuthEmails, email)
		user.dashboardAuthEmails = slices.Delete(user.dashboardAuthEmails, i, i+1)
		authentication.context.storage.users[username] = user
	}

	return authentication.context.storage.writeToFile()
}

func (authentication *dashboardViaEmailAuthentication) ClearAllEmails(username string) error {
	if len(username) <= 0 {
		return errors.New("username required")
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	user.dashboardAuthEmails = []string{}
	authentication.context.storage.users[username] = user

	return authentication.context.storage.writeToFile()
}
