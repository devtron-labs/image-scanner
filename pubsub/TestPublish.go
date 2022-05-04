package pubsub

import (
	"encoding/json"
	"github.com/nats-io/nats.go"

	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/internal/util"
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
	err = AddStream(impl.pubSubClient.JetStrContext, IMAGE_SCANNER_STREAM)
	if err != nil {
		impl.logger.Errorw("Error while adding stream", "error", err)
	}

	//Generate random string for passing as Header Id in message
	randString := "MsgHeaderId-" + util.Generate(10)
	_, err = impl.pubSubClient.JetStrContext.Publish(channel, body, nats.MsgId(randString))
	if err != nil {
		impl.logger.Errorw("Error while publishing request", "topic", channel, "error", err)
	}
	return err
}
