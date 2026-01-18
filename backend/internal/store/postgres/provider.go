package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Provider struct {
	dsn  string
	once sync.Once
	pool *pgxpool.Pool
	err  error
}

func NewProvider(dsn string) *Provider {
	return &Provider{dsn: dsn}
}

// Pool initializes (once) and returns pgx pool. No migrations performed.
func (p *Provider) Pool(ctx context.Context) (*pgxpool.Pool, error) {
	p.once.Do(func() {
		dsn := strings.TrimSpace(p.dsn)
		if dsn == "" {
			p.err = errors.New("PG_DSN is empty")
			return
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			p.err = err
			return
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			p.err = err
			return
		}
		p.pool = pool
	})
	return p.pool, p.err
}
