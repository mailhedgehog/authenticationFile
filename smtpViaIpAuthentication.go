package authenticationFile

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
)

type smtpViaIpAuthentication struct {
	context *storageContext
}

func (authentication *smtpViaIpAuthentication) Enabled() bool {
	return authentication.context.config.Smtp.ViaIpAuthentication.Enabled
}

func (authentication *smtpViaIpAuthentication) Authenticate(username string, ip string) bool {
	if !authentication.Enabled() {
		return true
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return false
	}

	return slices.Contains(user.smtpAuthIPs, ip)
}

func (authentication *smtpViaIpAuthentication) AddIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.smtpAuthIPs, ip) {
		return nil
	}

	user.smtpAuthIPs = append(user.smtpAuthIPs, ip)
	authentication.context.storage.users[username] = user

	return authentication.context.storage.writeToFile()
}

func (authentication *smtpViaIpAuthentication) DeleteIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := authentication.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.smtpAuthIPs, ip) {
		i := slices.Index(user.smtpAuthIPs, ip)
		user.smtpAuthIPs = slices.Delete(user.smtpAuthIPs, i, i+1)
		authentication.context.storage.users[username] = user
	}

	return authentication.context.storage.writeToFile()
}

func (authentication *smtpViaIpAuthentication) ClearAllIps(username string) error {
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

	user.smtpAuthIPs = []string{}
	authentication.context.storage.users[username] = user

	return authentication.context.storage.writeToFile()
}
