package logger

import (
	"fmt"
	"github.com/caarlos0/env/v6"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
)

func NewSugardLogger() *zap.SugaredLogger {
	l, err := InitLogger()
	if err != nil {
		panic("failed to create the default logger: " + err.Error())
	}
	return l
}

func NewHttpClient() *http.Client {
	return http.DefaultClient
}

type LogConfig struct {
	Level int `env:"LOG_LEVEL" envDefault:"0"` // default info
}

func InitLogger() (*zap.SugaredLogger, error) {
	cfg := &LogConfig{}
	err := env.Parse(cfg)
	if err != nil {
		fmt.Println("failed to parse logger env config: " + err.Error())
		return nil, err
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.Level(cfg.Level))
	l, err := config.Build()
	if err != nil {
		fmt.Println("failed to create the default logger: " + err.Error())
		return nil, err
	}
	logger := l.Sugar()
	return logger, nil
}
