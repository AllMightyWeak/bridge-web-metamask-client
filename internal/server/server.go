package server

import (
	"log/slog"
	"testMM/internal/config"
	"testMM/internal/handlers"
	"testMM/internal/middleware"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg config.Config
	log *slog.Logger
	r   *gin.Engine
}

func New(cfg config.Config, log *slog.Logger, h *handlers.Handlers, mw *middleware.Set) *Server {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(mw.CORS)

	RegisterRoutes(r, h, mw)

	return &Server{cfg: cfg, log: log, r: r}
}

func (s *Server) Run() error {
	s.log.Info("listening", "addr", s.cfg.ListenAddr)
	return s.r.Run(s.cfg.ListenAddr)
}
