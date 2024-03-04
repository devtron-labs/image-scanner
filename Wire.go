//go:build wireinject
// +build wireinject

package main

import (
	"github.com/google/wire"
)

func InitializeApp() (*App, error) {
	wire.Build(
		ImageScannerWireSet,
	)
	return &App{}, nil
}
