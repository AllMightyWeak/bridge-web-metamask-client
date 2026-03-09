package handlers

import (
	"log/slog"
	"testMM/backend/internal/auth"
	"testMM/backend/internal/config"
	"testMM/backend/internal/eth"
	"testMM/backend/internal/nftscan"
	"testMM/backend/internal/scan"
	"testMM/backend/internal/store"
	"testMM/backend/internal/store/postgres"
)

type Handlers struct {
	Cfg config.Config
	Log *slog.Logger

	Auth      *auth.Service
	Contacts  store.ContactsRepo
	Esia      *auth.EsiaService
	EsiaLinks store.EsiaLinkRepo
	Eth       *eth.RPCService

	PG *postgres.Provider // для init подключения после успешной авторизации

	NftWatcher *nftscan.Watcher

	TxScanner *scan.TxScanner
}

func New(
	cfg config.Config,
	log *slog.Logger,
	authSvc *auth.Service,
	esiaSvc *auth.EsiaService,
	esiaLinks store.EsiaLinkRepo,
	contacts store.ContactsRepo,
	ethSvc *eth.RPCService,
	pg *postgres.Provider,
	watcher *nftscan.Watcher,
	scanner *scan.TxScanner,
) *Handlers {
	return &Handlers{
		Cfg:        cfg,
		Log:        log,
		Auth:       authSvc,
		Esia:       esiaSvc,
		EsiaLinks:  esiaLinks,
		Contacts:   contacts,
		Eth:        ethSvc,
		PG:         pg,
		NftWatcher: watcher,
		TxScanner:  scanner,
	}
}
