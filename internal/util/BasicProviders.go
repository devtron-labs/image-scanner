package util

import (
	"go.uber.org/zap"
)

var (
	// Logger is the defaut logger
	logger *zap.SugaredLogger
	//FIXME: remove this
	//defer Logger.Sync()
)

// Deprecated: instead calling this method inject logger from wire
func GetLogger() *zap.SugaredLogger {
	return logger
}



func init() {
	l, err := zap.NewProduction()
	if err != nil {
		panic("failed to create the default logger: " + err.Error())
	}
	logger = l.Sugar()
}

