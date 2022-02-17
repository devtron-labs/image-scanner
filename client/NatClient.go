package client

import (
	"time"

	"github.com/caarlos0/env"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

const (
	TOPIC_CI_SCAN         = "CI-SCAN"
	TOPIC_CI_SCAN_GRP     = "CI-SCAN-GRP-1"
	TOPIC_CI_SCAN_DURABLE = "CI-SCAN-DURABLE-1"
)

type PubSubClient struct {
	logger        *zap.SugaredLogger
	JetStrContext nats.JetStreamContext
}

type PubSubConfig struct {
	NatsServerHost string `env:"NATS_SERVER_HOST" envDefault:"nats://localhost:4222"`
}

func NewPubSubClient(logger *zap.SugaredLogger) (*PubSubClient, error) {

	cfg := &PubSubConfig{}
	err := env.Parse(cfg)
	if err != nil {
		logger.Error("err", err)
		return &PubSubClient{}, err
	}

	nc, err := nats.Connect(cfg.NatsServerHost, nats.ReconnectWait(10*time.Second), nats.MaxReconnects(100))
	if err != nil {
		logger.Error("err", err)
		return &PubSubClient{}, err
	}
	//Create a jetstream context
	js, _ := nc.JetStream()

	natsClient := &PubSubClient{
		logger:        logger,
		JetStrContext: js,
	}
	return natsClient, nil
}
