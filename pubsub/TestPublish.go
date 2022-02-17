package pubsub

import (
	"encoding/json"

	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/internal/util"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/nats-io/nats.go"
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
	streamInfo, strInfoErr := impl.pubSubClient.JetStrContext.StreamInfo(channel)
	if strInfoErr != nil {
		impl.logger.Errorw("Error while getting stream infor", "topic", channel, "error", strInfoErr)
	}
	if streamInfo == nil {
		//Stream doesn not exist already, create a new stream from jetStreamContext
		_, addStrError := impl.pubSubClient.JetStrContext.AddStream(&nats.StreamConfig{
			Name:     channel,
			Subjects: []string{channel + ".*"},
		})
		if addStrError != nil {
			impl.logger.Errorw("Error while creating stream", "topic", channel, "error", addStrError)
		}
	}

	//Generate random string for passing as Header Id in message
	randString := "MsgHeaderId-" + util.Generate(10)
	_, pubErr := impl.pubSubClient.JetStrContext.Publish(channel, body, nats.MsgId(randString))
	if pubErr != nil {
		impl.logger.Errorw("Error while publishing request", "topic", channel, "error", pubErr)
	}
	return err
}
