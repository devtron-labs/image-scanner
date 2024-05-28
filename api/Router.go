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

package api

import (
	"encoding/json"
	"github.com/devtron-labs/common-lib/monitoring"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
)

type Router struct {
	logger           *zap.SugaredLogger
	Router           *mux.Router
	restHandler      RestHandler
	monitoringRouter *monitoring.MonitoringRouter
}

func NewRouter(logger *zap.SugaredLogger, restHandler RestHandler, monitoringRouter *monitoring.MonitoringRouter) *Router {
	return &Router{logger: logger, Router: mux.NewRouter(), restHandler: restHandler, monitoringRouter: monitoringRouter}
}

func (r Router) Init() {
	r.Router.StrictSlash(true)
	pProfListenerRouter := r.Router.PathPrefix("/image-scanner/debug/pprof/").Subrouter()
	statsVizRouter := r.Router.PathPrefix("/image-scanner").Subrouter()
	r.monitoringRouter.InitMonitoringRouter(pProfListenerRouter, statsVizRouter, "/image-scanner")
	r.Router.Handle("/metrics", promhttp.Handler())
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
