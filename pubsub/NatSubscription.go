package pubsub

import (
	"encoding/json"
	"github.com/devtron-labs/image-scanner/client"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
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
	clairService clairService.ClairService
}

func NewNatSubscription(pubSubClient *client.PubSubClient,
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
		_, err = impl.clairService.ScanImage(scanConfig)
		if err != nil {
			impl.logger.Infow("err in process msg", "err", err)
			return
		}
	}, stan.DurableName(client.TOPIC_CI_SCAN_DURABLE), stan.StartWithLastReceived(), stan.AckWait(time.Duration(impl.pubSubClient.AckDuration)*time.Second), stan.SetManualAckMode(), stan.MaxInflight(1))
	//s.Close()
	return err
}
