package pubsub

import (
	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
)

type TestPublish interface {
	PublishForScan(channel string, payload interface{}) error
}

type TestPublishImpl struct {
	pubSubClient *client.PubSubClient
	logger       *zap.SugaredLogger
	klarService  klarService.KlarService
}

func NewTestPublishImpl(pubSubClient *client.PubSubClient,
	logger *zap.SugaredLogger, klarService klarService.KlarService) *TestPublishImpl {
	ns := &TestPublishImpl{
		pubSubClient: pubSubClient,
		logger:       logger,
		klarService:  klarService,
	}
	return ns
}

func (impl *TestPublishImpl) PublishForScan(channel string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	err = impl.pubSubClient.Conn.Publish(channel, body)
	fmt.Println(body)
	return err
}
