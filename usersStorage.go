package authenticationFile

import (
	"errors"
	"github.com/mailhedgehog/contracts"
	"strings"
)

type usersStorage struct{}

func (storage *usersStorage) Exists(username string) bool {
	_, ok := fileAuthentication.users[username]

	return ok
}

func (storage *usersStorage) Add(username string) error {
	if len(username) <= 0 {
		return errors.New("username and httpPassHash required")
	}

	fileAuthentication.initUsers()

	fileAuthentication.users[username] = userInfo{
		username: username,
	}

	return fileAuthentication.writeToFile()
}

func (storage *usersStorage) Delete(username string) error {
	delete(fileAuthentication.users, username)

	return fileAuthentication.writeToFile()
}

func (storage *usersStorage) List(searchQuery string, offset, limit int) ([]contracts.UserResource, int, error) {
	keys := make([]string, 0, len(fileAuthentication.users))
	for k, _ := range fileAuthentication.users {
		if len(searchQuery) > 0 {
			if strings.Contains(k, searchQuery) {
				keys = append(keys, k)
			}
		} else {
			keys = append(keys, k)
		}
	}

	endIndex := len(keys)
	if offset+limit < len(keys) {
		endIndex = offset + limit
	}
	if offset < 0 || offset > endIndex {
		offset = 0
	}
	slice := keys[offset:endIndex]
	var resources []contracts.UserResource
	for _, username := range slice {
		user, ok := fileAuthentication.users[username]
		if !ok {
			continue
		}
		resources = append(resources, contracts.UserResource{
			Username:            user.username,
			SmtpAuthIPs:         user.smtpAuthIPs,
			SmtpAllowListedIPs:  user.smtpAllowListedIPs,
			DashboardAuthEmails: user.dashboardAuthEmails,
		})
	}

	return resources, len(keys), nil
}
