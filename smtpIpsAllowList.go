package authenticationFile

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
)

type smtpIpsAllowList struct {
	context *storageContext
}

func (allowlist *smtpIpsAllowList) Enabled() bool {
	return allowlist.context.config.Smtp.IpsAllowList.Enabled
}

func (allowlist *smtpIpsAllowList) Allowed(username string, ip string) bool {
	if !allowlist.Enabled() {
		return true
	}

	user, ok := allowlist.context.storage.users[username]
	if !ok {
		return false
	}

	return slices.Contains(user.smtpAllowListedIPs, ip)
}

func (allowlist *smtpIpsAllowList) AddIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := allowlist.context.storage.users[username]
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
	allowlist.context.storage.users[username] = user

	return allowlist.context.storage.writeToFile()
}

func (allowlist *smtpIpsAllowList) DeleteIp(username string, ip string) error {
	if len(username) <= 0 || len(ip) <= 0 {
		return errors.New("username and ip required")
	}

	user, ok := allowlist.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	if slices.Contains(user.smtpAllowListedIPs, ip) {
		i := slices.Index(user.smtpAllowListedIPs, ip)
		user.smtpAllowListedIPs = slices.Delete(user.smtpAllowListedIPs, i, i+1)
		allowlist.context.storage.users[username] = user
	}

	return allowlist.context.storage.writeToFile()
}

func (allowlist *smtpIpsAllowList) ClearAllIps(username string) error {
	if len(username) <= 0 {
		return errors.New("username required")
	}

	user, ok := allowlist.context.storage.users[username]
	if !ok {
		return errors.New(fmt.Sprintf(
			"User with such username [%s] not found.",
			username,
		))
	}

	user.smtpAllowListedIPs = []string{}
	allowlist.context.storage.users[username] = user

	return allowlist.context.storage.writeToFile()
}
