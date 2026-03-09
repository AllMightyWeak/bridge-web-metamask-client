package postgres

import (
	"context"
	"errors"
	"strings"
	"testMM/backend/internal/store"

	"github.com/jackc/pgx/v5"
)

type esiaLinkRepo struct {
	pg *Provider
}

func NewEsiaLinkRepo(pg *Provider) store.EsiaLinkRepo {
	return &esiaLinkRepo{pg: pg}
}

func (r *esiaLinkRepo) SaveLink(ctx context.Context, esiaUserID, ethAddress string, chainID uint64) error {
	pool, err := r.pg.Pool(ctx)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO esia_wallet_links (esia_user_id, eth_address, chain_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (esia_user_id) DO UPDATE
             SET eth_address = EXCLUDED.eth_address,
                 chain_id    = EXCLUDED.chain_id,
                 linked_at   = now()`,
		strings.TrimSpace(esiaUserID),
		strings.ToLower(strings.TrimSpace(ethAddress)),
		chainID,
	)
	return err
}

func (r *esiaLinkRepo) GetByEsiaID(ctx context.Context, esiaUserID string) (store.EsiaLink, error) {
	pool, err := r.pg.Pool(ctx)
	if err != nil {
		return store.EsiaLink{}, err
	}
	var out store.EsiaLink
	err = pool.QueryRow(ctx,
		`SELECT esia_user_id, eth_address, chain_id
         FROM esia_wallet_links
         WHERE esia_user_id = $1`,
		strings.TrimSpace(esiaUserID),
	).Scan(&out.EsiaUserID, &out.EthAddress, &out.ChainID)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.EsiaLink{}, nil
	}
	return out, err
}
