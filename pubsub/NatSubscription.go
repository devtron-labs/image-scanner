package pubsub

import (
	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/klarService"

	"encoding/json"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type NatSubscription interface {
	Subscribe() error
}

type NatSubscriptionImpl struct {
	pubSubClient *client.PubSubClient
	logger       *zap.SugaredLogger
	klarService  klarService.KlarService
}

func NewNatSubscription(pubSubClient *client.PubSubClient,
	logger *zap.SugaredLogger, klarService klarService.KlarService) (*NatSubscriptionImpl, error) {
	ns := &NatSubscriptionImpl{
		pubSubClient: pubSubClient,
		logger:       logger,
		klarService:  klarService,
	}
	err := AddStream(ns.pubSubClient.JetStrContext, IMAGE_SCANNER_STREAM)
	if err != nil {
		ns.logger.Errorw("Error while adding stream", "error", err)
	}
	return ns, ns.Subscribe()
}

func (impl *NatSubscriptionImpl) Subscribe() error {
	_, err := impl.pubSubClient.JetStrContext.QueueSubscribe(TOPIC_CI_SCAN, TOPIC_CI_SCAN_GRP, func(msg *nats.Msg) {
		impl.logger.Debugw("received msg", "msg", msg)
		defer msg.Ack()
		scanConfig := &common.ScanEvent{}
		err := json.Unmarshal(msg.Data, scanConfig)
		if err != nil {
			impl.logger.Errorw("err in reading msg", "err", err, "msg", string(msg.Data))
			return
		}
		impl.logger.Infow("scanConfig unmarshal data", "scanConfig", scanConfig)

		_, err = impl.klarService.Process(scanConfig)
		if err != nil {
			impl.logger.Infow("err in process msg", "err", err)
			return
		}
	}, nats.Durable(TOPIC_CI_SCAN_DURABLE), nats.DeliverLast(), nats.ManualAck(), nats.BindStream(IMAGE_SCANNER_STREAM))
	return err
}
