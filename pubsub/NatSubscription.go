package pubsub

import (
	"encoding/json"
	pubsub1 "github.com/devtron-labs/common-lib/pubsub-lib"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
	"go.uber.org/zap"
)

type NatSubscription interface {
	Subscribe() error
}

type NatSubscriptionImpl struct {
	pubSubClient *pubsub1.PubSubClientServiceImpl
	logger       *zap.SugaredLogger
	clairService clairService.ClairService
}

func NewNatSubscription(pubSubClient *pubsub1.PubSubClientServiceImpl,
	logger *zap.SugaredLogger,
	clairService clairService.ClairService) (*NatSubscriptionImpl, error) {
	ns := &NatSubscriptionImpl{
		pubSubClient: pubSubClient,
		logger:       logger,
		clairService: clairService,
	}
	return ns, ns.Subscribe()
}

func (impl *NatSubscriptionImpl) Subscribe() error {
	callback := func(msg *pubsub1.PubSubMsg) {
		impl.logger.Debugw("received msg", "msg", msg)
		//defer msg.Ack()
		scanConfig := &common.ScanEvent{}
		err := json.Unmarshal([]byte(msg.Data), scanConfig)
		if err != nil {
			impl.logger.Errorw("err in reading msg", "err", err, "msg", string(msg.Data))
			return
		}
		impl.logger.Infow("scanConfig unmarshal data", "scanConfig", scanConfig)

		//scanConfig.Image = "quay.io/coreos/clair:v2.0.0"
		_, err = impl.clairService.ScanImage(scanConfig)
		if err != nil {
			impl.logger.Infow("err in process msg", "err", err)
			return
		}
	}
	err := impl.pubSubClient.Subscribe(pubsub1.TOPIC_CI_SCAN, callback)
	if err != nil {
		impl.logger.Errorw("Error while subscribing to pubsub", "topic", pubsub1.TOPIC_CI_SCAN, "error", err)
	}
	return err
}
