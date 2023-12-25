package authenticationFile

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/logger"
	"os"
	"strings"
)

type userInfo struct {
	username            string
	dashboardPass       string
	smtpPass            string
	smtpAuthIPs         []string
	smtpAllowListedIPs  []string
	dashboardAuthEmails []string
}

// FileAuthentication represents the authentication handler using file
type FileAuthentication struct {
	filePath string
	config   *contracts.AuthenticationConfig
	users    map[string]userInfo
}

// authFile scan file and add users to memory
func (fileAuth *FileAuthentication) authFile() int {
	fileAuth.users = nil

	if len(fileAuth.filePath) <= 0 {
		logManager().Debug("File auth empty.")
		return 0
	}

	file, err := os.Open(fileAuth.filePath)
	logger.PanicIfError(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		err := fileAuth.addUserFromFileLine(scanner.Text())
		if err != nil {
			logManager().Notice(err.Error())
		} else {
		}
	}

	if fileAuth.users == nil {
		return 0
	}
	return len(fileAuth.users)
}

func (fileAuth *FileAuthentication) addUserFromFileLine(line string) error {
	line = strings.TrimSpace(line)
	infoSlice := strings.Split(line, ":")
	for i := range infoSlice {
		infoSlice[i] = strings.TrimSpace(infoSlice[i])
	}

	if len(infoSlice) < 1 {
		return errors.New("at least should be present username")
	}

	if len(infoSlice[0]) <= 0 {
		return errors.New("username can't be empty")
	}

	smtpPass := infoSlice[1]
	if len(infoSlice) > 2 && len(infoSlice[2]) > 0 {
		smtpPass = infoSlice[2]
	}

	fileAuth.initUsers()

	noPassIPs := []string{}
	if len(infoSlice) > 3 && len(infoSlice[3]) > 0 {
		noPassIPs = strings.Split(infoSlice[3], ",")
	}

	restrictedIPs := []string{}
	if len(infoSlice) > 3 && len(infoSlice[4]) > 0 {
		restrictedIPs = strings.Split(infoSlice[4], ",")
	}

	emails := []string{}
	if len(infoSlice) > 4 && len(infoSlice[5]) > 0 {
		emails = strings.Split(infoSlice[5], ",")
	}

	fileAuth.users[infoSlice[0]] = userInfo{
		username:            infoSlice[0],
		dashboardPass:       infoSlice[1],
		smtpPass:            smtpPass,
		smtpAuthIPs:         noPassIPs,
		smtpAllowListedIPs:  restrictedIPs,
		dashboardAuthEmails: emails,
	}

	logManager().Debug(fmt.Sprintf("Processes users: '%s'", infoSlice[0]))

	return nil
}

func (fileAuth *FileAuthentication) writeToFile() error {
	file, err := os.OpenFile(fileAuth.filePath, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		return err
	}
	defer file.Close()

	file.Truncate(0)
	for _, userInfo := range fileAuth.users {
		smtpPass := ""
		if userInfo.dashboardPass != userInfo.smtpPass {
			smtpPass = userInfo.smtpPass
		}
		_, err := file.WriteString(fmt.Sprintf(
			"%s:%s:%s:%s:%s:%s\n",
			userInfo.username,
			userInfo.dashboardPass,
			smtpPass,
			strings.Join(userInfo.smtpAuthIPs, ","),
			strings.Join(userInfo.smtpAllowListedIPs, ","),
			strings.Join(userInfo.dashboardAuthEmails, ","),
		))
		if err != nil {
			return err
		}
	}

	return nil
}

func (fileAuth *FileAuthentication) initUsers() {
	if fileAuth.users == nil {
		fileAuth.users = make(map[string]userInfo)
	}
}

func (fileAuth *FileAuthentication) SMTP() contracts.SmtpAuthentication {
	return &smtpAuthentication{}
}
func (fileAuth *FileAuthentication) Dashboard() contracts.DashboardAuthentication {
	return &dashboardAuthentication{}
}
func (fileAuth *FileAuthentication) UsersStorage() contracts.UsersStorage {
	return &usersStorage{}
}
