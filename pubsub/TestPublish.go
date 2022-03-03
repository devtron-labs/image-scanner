package pubsub

import (
	"encoding/json"
	"fmt"
	"github.com/devtron-labs/image-scanner/client"
	"go.uber.org/zap"
)

type TestPublish interface {
	PublishForScan(channel string, payload interface{}) error
}

type TestPublishImpl struct {
	pubSubClient *client.PubSubClient
	logger       *zap.SugaredLogger
}

func NewTestPublishImpl(pubSubClient *client.PubSubClient,
	logger *zap.SugaredLogger) *TestPublishImpl {
	ns := &TestPublishImpl{
		pubSubClient: pubSubClient,
		logger:       logger,
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
