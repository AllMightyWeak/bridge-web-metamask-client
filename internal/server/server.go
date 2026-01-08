package server

import (
	"context"
	"log/slog"
	"testMM/internal/config"
	"testMM/internal/handlers"
	"testMM/internal/middleware"
	"testMM/internal/nftscan"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg config.Config
	log *slog.Logger
	r   *gin.Engine

	nftWatcher *nftscan.Watcher
}

func New(cfg config.Config, log *slog.Logger, h *handlers.Handlers, mw *middleware.Set, watcher *nftscan.Watcher) *Server {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(mw.CORS)

	RegisterRoutes(r, h, mw)

	return &Server{cfg: cfg, log: log, r: r, nftWatcher: watcher}
}

func (s *Server) Run() error {
	if s.nftWatcher != nil {
		ctx := context.Background()
		s.nftWatcher.Start(ctx) // внутри Start уже go-routine, либо сам сделай go
		s.log.Info("nft watcher started")
	}

	s.log.Info("listening", "addr", s.cfg.ListenAddr)
	return s.r.Run(s.cfg.ListenAddr)
}
