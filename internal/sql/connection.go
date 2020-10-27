package sql

import (
	"github.com/caarlos0/env"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"time"
)

type Config struct {
	Addr            string `env:"PG_ADDR" envDefault:"127.0.0.1"`
	Port            string `env:"PG_PORT" envDefault:"5432"`
	User            string `env:"PG_USER" envDefault:""`
	Password        string `env:"PG_PASSWORD" envDefault:""`
	Database        string `env:"PG_DATABASE" envDefault:"orchestrator"`
	ApplicationName string `env:"APP" envDefault:"image-scanner"`
	LogQuery        bool   `env:"PG_LOG_QUERY" envDefault:"true"`
}

func GetConfig() (*Config, error) {
	cfg := &Config{}
	err := env.Parse(cfg)
	return cfg, err
}

func NewDbConnection(cfg *Config, logger *zap.SugaredLogger) (*pg.DB, error) {
	options := pg.Options{
		Addr:            cfg.Addr + ":" + cfg.Port,
		User:            cfg.User,
		Password:        cfg.Password,
		Database:        cfg.Database,
		ApplicationName: cfg.ApplicationName,
	}
	dbConnection := pg.Connect(&options)
	//check db connection
	var test string
	_, err := dbConnection.QueryOne(&test, `SELECT 1`)

	if err != nil {
		logger.Errorw("error in connecting db ", "db", cfg, "err", err)
		return nil, err
	} else {
		logger.Infow("connected with db", "db", cfg)
	}
	//--------------
	if cfg.LogQuery {
		dbConnection.OnQueryProcessed(func(event *pg.QueryProcessedEvent) {
			query, err := event.FormattedQuery()
			if err != nil {
				panic(err)
			}
			logger.Infow("query time",
				"duration", time.Since(event.StartTime),
				"query", query)
		})
	}
	return dbConnection, err
}

//TODO: call it from somewhere
/*func closeConnection() error {
	return dbConnection.Close()
}*/
