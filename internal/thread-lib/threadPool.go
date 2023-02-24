package thread_lib

import (
	"github.com/caarlos0/env"
	"log"
)

type ThreadPool interface {
	StartThreadPool()
	AddThreadToExecutionQueue(thread func())
}

type ThreadPoolImpl struct {
	PoolThreadCount     int
	QueuedThreadChannel chan func()
}

type ThreadPoolConfig struct {
	PoolThreadCount int `env:"POOL_THREAD_COUNT" envDefault:"10"`
}

func GetThreadPoolConfig() (*ThreadPoolConfig, error) {
	config := &ThreadPoolConfig{}
	err := env.Parse(config)
	if err != nil {
		log.Println("error in parsing thread pool config from environment", "err", err)
		return config, err
	}
	return config, nil
}

func NewThreadPoolImpl() (*ThreadPoolImpl, error) {
	threadPoolConfig, err := GetThreadPoolConfig()
	if err != nil {
		return nil, err
	}
	poolThreadCount := threadPoolConfig.PoolThreadCount
	queueChannel := make(chan func(), poolThreadCount)
	return &ThreadPoolImpl{
		PoolThreadCount:     poolThreadCount,
		QueuedThreadChannel: queueChannel,
	}, nil
}

func (impl *ThreadPoolImpl) StartThreadPool() {
	for i := 0; i < impl.PoolThreadCount; i++ {
		go func(threadId int) {
			for threadFunc := range impl.QueuedThreadChannel {
				threadFunc()
			}
		}(i + 1)
	}
}

func (impl *ThreadPoolImpl) AddThreadToExecutionQueue(threadFunc func()) {
	impl.QueuedThreadChannel <- threadFunc
}
