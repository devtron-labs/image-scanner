/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
