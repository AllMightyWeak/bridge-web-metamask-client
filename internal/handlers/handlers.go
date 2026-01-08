package handlers

import (
	"log/slog"
	"testMM/internal/auth"
	"testMM/internal/config"
	"testMM/internal/eth"
	"testMM/internal/nftscan"
	"testMM/internal/store"
	"testMM/internal/store/postgres"
)

type Handlers struct {
	Cfg config.Config
	Log *slog.Logger

	Auth     *auth.Service
	Contacts store.ContactsRepo
	Eth      *eth.RPCService

	PG *postgres.Provider // для init подключения после успешной авторизации

	NftWatcher *nftscan.Watcher
}

func New(cfg config.Config, log *slog.Logger, authSvc *auth.Service, contacts store.ContactsRepo, ethSvc *eth.RPCService, pg *postgres.Provider, watcher *nftscan.Watcher) *Handlers {
	return &Handlers{
		Cfg:        cfg,
		Log:        log,
		Auth:       authSvc,
		Contacts:   contacts,
		Eth:        ethSvc,
		PG:         pg,
		NftWatcher: watcher,
	}
}
