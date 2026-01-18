package app

import (
	"log/slog"
	"os"
	"testMM/backend/internal/auth"
	"testMM/backend/internal/config"
	"testMM/backend/internal/eth"
	"testMM/backend/internal/handlers"
	"testMM/backend/internal/middleware"
	"testMM/backend/internal/nftscan"
	"testMM/backend/internal/scan"
	"testMM/backend/internal/server"
	"testMM/backend/internal/store/postgres"
)

func Wire(cfg config.Config) (*App, error) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	scanner, err := nftscan.NewScanner(cfg.WNFTRpcURL, cfg.WNFTAddr)
	if err != nil {
		return nil, err
	}
	watcher := nftscan.NewWatcher(scanner, cfg.NFTScanInterval)

	pg := postgres.NewProvider(cfg.PgDSN)

	authSvc := auth.NewService(cfg)
	ethSvc := eth.NewRPCService(cfg.RPCByChainID)
	contactsRepo := postgres.NewContactsRepo(pg)

	rpcProv := &scan.SimpleRPCProvider{RPCByNetwork: cfg.RPCByNetwork}
	txScanner, err := scan.NewTxScanner(rpcProv)
	if err != nil {
		return nil, err
	}

	h := handlers.New(cfg, log, authSvc, contactsRepo, ethSvc, pg, watcher, txScanner)
	mw := middleware.NewSet(cfg, authSvc)
	http := server.New(cfg, log, h, mw, watcher)

	return New(http), nil
}
