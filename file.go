package authenticationFile

import (
	"github.com/mailhedgehog/contracts"
	"github.com/mailhedgehog/logger"
)

var configuredLogger *logger.Logger

func logManager() *logger.Logger {
	if configuredLogger == nil {
		configuredLogger = logger.CreateLogger("authenticationFile")
	}
	return configuredLogger
}

type StorageConfiguration struct {
	Path string `yaml:"path"`
}

var fileAuthentication *FileAuthentication

func CreateFileAuthentication(storageConfiguration *StorageConfiguration, config *contracts.AuthenticationConfig) *FileAuthentication {
	fileAuthentication = &FileAuthentication{
		filePath: storageConfiguration.Path,
		config:   config,
	}
	fileAuthentication.authFile()
	return fileAuthentication
}
