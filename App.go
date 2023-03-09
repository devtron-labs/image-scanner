package main

import (
	"context"
	"fmt"
	thread_lib "github.com/devtron-labs/image-scanner/internal/thread-lib"
	"net/http"
	"os"
	"time"

	client "github.com/devtron-labs/common-lib/pubsub-lib"
	"github.com/devtron-labs/image-scanner/api"
	"github.com/devtron-labs/image-scanner/pubsub"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type App struct {
	MuxRouter        *api.MuxRouter
	Logger           *zap.SugaredLogger
	server           *http.Server
	db               *pg.DB
	natsSubscription *pubsub.NatSubscriptionImpl
	pubSubClient     *client.PubSubClientServiceImpl
	threadPool       thread_lib.ThreadPool
}

func NewApp(MuxRouter *api.MuxRouter, Logger *zap.SugaredLogger,
	db *pg.DB, natsSubscription *pubsub.NatSubscriptionImpl,
	pubSubClient *client.PubSubClientServiceImpl, threadPool thread_lib.ThreadPool) *App {
	return &App{
		MuxRouter:        MuxRouter,
		Logger:           Logger,
		db:               db,
		natsSubscription: natsSubscription,
		pubSubClient:     pubSubClient,
		threadPool:       threadPool,
	}
}

func (app *App) Start() {
	port := 8080 //TODO: extract from environment variable
	app.Logger.Infow("starting server on ", "port", port)
	app.MuxRouter.Init()
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: app.MuxRouter.Router}
	app.server = server
	err := server.ListenAndServe()
	if err != nil {
		app.Logger.Errorw("error in startup", "err", err)
		os.Exit(2)
	}
	// starting thread pool
	app.threadPool.StartThreadPool()
}

func (app *App) Stop() {
	app.Logger.Infow("image scanner shutdown initiating")
	timeoutContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.Logger.Infow("closing router")
	err := app.server.Shutdown(timeoutContext)
	if err != nil {
		app.Logger.Errorw("error in mux router shutdown", "err", err)
	}

	//app.logger.Infow("Draining nats connection")
	//Drain nats connection
	//err = app.pubSubClient.Conn.Drain()
	//
	//if err != nil {
	//	app.logger.Errorw("Error while draining Nats", "error", err)
	//}

	app.Logger.Infow("closing db connection")
	err = app.db.Close()
	if err != nil {
		app.Logger.Errorw("Error while closing DB", "error", err)
	}

	app.Logger.Infow("housekeeping done. exiting now")
}
