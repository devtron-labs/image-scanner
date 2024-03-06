//go:build wireinject
// +build wireinject

package main

import (
	"github.com/devtron-labs/image-scanner/pkg"
	"github.com/google/wire"
)

func InitializeApp() (*App, error) {
	wire.Build(
		NewApp,
		pkg.ImageScannerPkgWireSet,
	)
	return &App{}, nil
}
