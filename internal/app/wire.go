package app

import (
	"log/slog"
	"os"
	"testMM/internal/auth"
	"testMM/internal/config"
	"testMM/internal/eth"
	"testMM/internal/handlers"
	"testMM/internal/middleware"
	"testMM/internal/nftscan"
	"testMM/internal/server"
	"testMM/internal/store/postgres"
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

	h := handlers.New(cfg, log, authSvc, contactsRepo, ethSvc, pg, watcher)
	mw := middleware.NewSet(cfg, authSvc)
	http := server.New(cfg, log, h, mw, watcher)

	return New(http), nil
}
