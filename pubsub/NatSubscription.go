package pubsub

import (
	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/klarService"

	/*"github.com/devtron-labs/image-scanner/pkg"*/
	/*"github.com/devtron-labs/image-scanner/pkg"*/
	"encoding/json"
	"github.com/nats-io/stan.go"
	"go.uber.org/zap"
	"time"
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
	return ns, ns.Subscribe()
}

func (impl *NatSubscriptionImpl) Subscribe() error {
	_, err := impl.pubSubClient.Conn.QueueSubscribe(client.TOPIC_CI_SCAN, client.TOPIC_CI_SCAN_GRP, func(msg *stan.Msg) {
		impl.logger.Debugw("received msg", "msg", msg)
		defer msg.Ack()
		scanConfig := &common.ScanEvent{}
		err := json.Unmarshal(msg.Data, scanConfig)
		if err != nil {
			impl.logger.Errorw("err in reading msg", "err", err, "msg", string(msg.Data))
			return
		}
		impl.logger.Infow("scanConfig unmarshal data", "scanConfig", scanConfig)

		//scanConfig.Image = "quay.io/coreos/clair:v2.0.0"
		_, err = impl.klarService.Process(scanConfig)
		if err != nil {
			impl.logger.Infow("err in process msg", "err", err)
			return
		}
	}, stan.DurableName(client.TOPIC_CI_SCAN_DURABLE), stan.StartWithLastReceived(), stan.AckWait(time.Duration(impl.pubSubClient.AckDuration)*time.Second), stan.SetManualAckMode(), stan.MaxInflight(1))
	//s.Close()
	return err
}
