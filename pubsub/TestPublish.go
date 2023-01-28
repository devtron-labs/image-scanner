package pubsub

import (
	"encoding/json"
	pubsub "github.com/devtron-labs/common-lib/pubsub-lib"
	"go.uber.org/zap"
)

type TestPublish interface {
	PublishForScan(channel string, payload interface{}) error
}

type TestPublishImpl struct {
	pubSubClient *pubsub.PubSubClientServiceImpl
	logger       *zap.SugaredLogger
}

func NewTestPublishImpl(pubSubClient *pubsub.PubSubClientServiceImpl,
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
	err = impl.pubSubClient.Publish(channel, string(body))
	if err != nil {
		impl.logger.Errorw("Error while publishing request", "topic", channel, "error", err)
	}
	return err
}
