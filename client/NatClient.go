package client

import (
	"github.com/caarlos0/env"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	"go.uber.org/zap"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"
)

const (
	TOPIC_CI_SCAN         = "CI-SCAN"
	TOPIC_CI_SCAN_GRP     = "CI-SCAN-GRP-1"
	TOPIC_CI_SCAN_DURABLE = "CI-SCAN-DURABLE-1"
)

type PubSubClient struct {
	logger      *zap.SugaredLogger
	Conn        stan.Conn
	AckDuration int
}

type PubSubConfig struct {
	NatsServerHost string `env:"NATS_SERVER_HOST" envDefault:"nats://localhost:4222"`
	ClusterId      string `env:"CLUSTER_ID" envDefault:"devtron-stan"`
	ClientId       string `env:"CLIENT_ID" envDefault:"image-scanner"`
	AckDuration    string `env:"ACK_DURATION" envDefault:"30"`
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

	s := rand.NewSource(time.Now().UnixNano())
	uuid := rand.New(s)
	uniqueClienId := "image-scanner-" + strconv.Itoa(uuid.Int())

	sc, err := stan.Connect(cfg.ClusterId, uniqueClienId, stan.NatsConn(nc))
	if err != nil {
		log.Println("err", err)
		os.Exit(1)
	}
	ack, err := strconv.Atoi(cfg.AckDuration)
	if err != nil {
		log.Println("err", err)
		os.Exit(1)
	}
	natsClient := &PubSubClient{
		logger:      logger,
		Conn:        sc,
		AckDuration: ack,
	}
	return natsClient, nil
}
