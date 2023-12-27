package authenticationFile

import (
	"errors"
	"github.com/mailhedgehog/contracts"
	"strings"
)

type usersStorage struct {
	context *storageContext
}

func (storage *usersStorage) Exists(username string) bool {
	_, ok := storage.context.storage.users[username]

	return ok
}

func (storage *usersStorage) Add(username string) error {
	if len(username) <= 0 {
		return errors.New("username and httpPassHash required")
	}

	storage.context.storage.initUsers()

	storage.context.storage.users[username] = userInfo{
		username: username,
	}

	return storage.context.storage.writeToFile()
}

func (storage *usersStorage) Delete(username string) error {
	delete(storage.context.storage.users, username)

	return storage.context.storage.writeToFile()
}

func (storage *usersStorage) List(searchQuery string, offset, limit int) ([]contracts.UserResource, int, error) {
	keys := make([]string, 0, len(storage.context.storage.users))
	for k, _ := range storage.context.storage.users {
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
		user, ok := storage.context.storage.users[username]
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
