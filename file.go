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

func CreateFileAuthentication(storageConfiguration *StorageConfiguration, config *contracts.AuthenticationConfig) *FileAuthentication {
	storage := &FileAuthentication{
		context: &storageContext{
			filePath: storageConfiguration.Path,
			config:   config,
		}}

	storage.context.storage = storage

	storage.authFile()

	return storage
}
