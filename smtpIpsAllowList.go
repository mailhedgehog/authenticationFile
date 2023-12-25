package authenticationFile

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
)

type smtpIpsAllowList struct {
}

func (allowlist *smtpIpsAllowList) Enabled() bool {
	return fileAuthentication.config.Smtp.IpsAllowList.Enabled
}

func (allowlist *smtpIpsAllowList) Allowed(username string, ip string) bool {
	if !allowlist.Enabled() {
		return true
	}

	user, ok := fileAuthentication.users[username]
	if !ok {
		return false
	}

	if len(user.smtpAllowListedIPs) > 0 {
		return slices.Contains(user.smtpAllowListedIPs, ip)
	}

	return true
}

func (allowlist *smtpIpsAllowList) AddIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := fileAuthentication.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.smtpAllowListedIPs, ip) {
		return nil
	}

	user.smtpAllowListedIPs = append(user.smtpAllowListedIPs, ip)
	fileAuthentication.users[username] = user

	return fileAuthentication.writeToFile()
}

func (allowlist *smtpIpsAllowList) DeleteIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := fileAuthentication.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.smtpAllowListedIPs, ip) {
		i := slices.Index(user.smtpAllowListedIPs, ip)
		user.smtpAllowListedIPs = slices.Delete(user.smtpAllowListedIPs, i, i+1)
		fileAuthentication.users[username] = user
	}

	return fileAuthentication.writeToFile()
}

func (allowlist *smtpIpsAllowList) ClearAllIps(username string) error {
	if len(username) <= 0 {
		return errors.New("username required")
	}

	user, ok := fileAuthentication.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	user.smtpAllowListedIPs = []string{}
	fileAuthentication.users[username] = user

	return fileAuthentication.writeToFile()
}
