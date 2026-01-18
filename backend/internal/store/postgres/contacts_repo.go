package postgres

import (
	"context"
	"strings"
	"testMM/backend/internal/store"
)

type contactsRepo struct {
	pg *Provider
}

func NewContactsRepo(pg *Provider) store.ContactsRepo {
	return &contactsRepo{pg: pg}
}

func (r *contactsRepo) Insert(ctx context.Context, userPubKey, contactPubKey, contactAddr, contactName, contactNetwork string) error {
	pool, err := r.pg.Pool(ctx)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx,
		`insert into contacts (user_pub_key, contact_pub_key, contact_addr, contact_name, contact_network)
		 values ($1, $2, $3, $4, $5)`,
		strings.ToLower(userPubKey),
		contactPubKey,
		strings.ToLower(contactAddr),
		contactName,
		contactNetwork,
	)
	return err
}

func (r *contactsRepo) List(ctx context.Context, userPubKey string) ([]store.Contact, error) {
	pool, err := r.pg.Pool(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx,
		`select contact_pub_key, contact_addr, contact_name, contact_network
		 from contacts
		 where user_pub_key = $1
		 order by contact_name asc`,
		strings.ToLower(userPubKey),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]store.Contact, 0)
	for rows.Next() {
		var it store.Contact
		if err := rows.Scan(&it.PublicKey, &it.Address, &it.Name, &it.Network); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// func (r *contactsRepo) GetContactKeyInfo(ctx context.Context, userPubKey, contactAddr string) (store.ContactKeyInfo, error) {
// pool, err := r.pg.Pool(ctx)
// if err != nil {
// 	return nil, err
// }
// 	var out store.ContactKeyInfo
// 	err = pool.QueryRow(ctx,
// 		`select contact_pub_key, contact_network
//          from contacts
//          where user_pub_key=$1 and contact_addr=$2`,
// 		strings.ToLower(userPubKey),
// 		strings.ToLower(contactAddr),
// 	).Scan(&out.PubKey, &out.Network)
// 	return out, err
// }

// func (r *contactsRepo) GetContactKeyInfo(ctx context.Context, userPubKey, contactAddr string) (store.ContactKeyInfo, error) {
// 	pool, err := r.pg.Pool(ctx)
// 	if err != nil {
// 		return store.ContactKeyInfo{}, err
// 	}

// 	var out store.ContactKeyInfo
// 	err = pool.QueryRow(ctx,
// 		`select contact_pub_key, contact_network
//          from contacts
//          where user_pub_key=$1 and contact_addr=$2`,
// 		strings.ToLower(userPubKey),
// 		strings.ToLower(contactAddr),
// 	).Scan(&out.PubKey, &out.Network)
// 	return out, err
// }

func (r *contactsRepo) GetContactKeyInfo(ctx context.Context, userPubKey, contactAddr string) (store.ContactKeyInfo, error) {
	var out store.ContactKeyInfo
	err := r.pg.pool.QueryRow(ctx,
		`select contact_pub_key, contact_network
         from contacts
         where user_pub_key=$1 and contact_addr=$2`,
		strings.ToLower(userPubKey),
		strings.ToLower(contactAddr),
	).Scan(&out.PubKey, &out.Network)
	return out, err
}
