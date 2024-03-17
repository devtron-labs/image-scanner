package roundTripper

import (
	"crypto/tls"
	"github.com/devtron-labs/image-scanner/common"
	"go.uber.org/zap"
	"net/http"
)

type RoundTripperService interface {
	GetRoundTripperTransport(scanEvent *common.ImageScanEvent) (http.RoundTripper, error)
}
type RoundTripperServiceImpl struct {
	Logger *zap.SugaredLogger
}

func NewRoundTripperServiceImpl(logger *zap.SugaredLogger) *RoundTripperServiceImpl {
	return &RoundTripperServiceImpl{
		Logger: logger,
	}
}

func (impl *RoundTripperServiceImpl) GetRoundTripperTransport(scanEvent *common.ImageScanEvent) (http.RoundTripper, error) {
	roundTripperTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return roundTripperTransport, nil
}
