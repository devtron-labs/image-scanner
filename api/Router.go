package api

import (
	"encoding/json"
	"github.com/devtron-labs/image-scanner/pprof"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"net/http"
)

type Router struct {
	logger      *zap.SugaredLogger
	Router      *mux.Router
	restHandler RestHandler
	pprofRouter pprof.PProfRouter
}

func NewRouter(logger *zap.SugaredLogger, restHandler RestHandler, pprofRouter pprof.PProfRouter) *Router {
	return &Router{logger: logger, Router: mux.NewRouter(), restHandler: restHandler, pprofRouter: pprofRouter}
}

func (r Router) Init() {
	r.Router.StrictSlash(true)
	pProfListenerRouter := r.Router.PathPrefix("/image-scanner/debug/pprof/").Subrouter()
	r.pprofRouter.InitPProfRouter(pProfListenerRouter)
	//r.Router.Handle("/metrics", promhttp.Handler())
	r.Router.Path("/health").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(200)
		response := Response{}
		response.Code = 200
		response.Result = "OK"
		b, err := json.Marshal(response)
		if err != nil {
			b = []byte("OK")
			r.logger.Errorw("Unexpected error in apiError", "err", err)
		}
		_, _ = writer.Write(b)
	})

	r.Router.Path("/scanner/image").HandlerFunc(r.restHandler.ScanForVulnerability).Methods("POST")
}
