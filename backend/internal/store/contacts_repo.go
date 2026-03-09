package store

import "context"

type Contact struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	Name      string `json:"name"`
	Network   string `json:"network"`
}

type ContactKeyInfo struct {
	PubKey  string
	Network string
}

type ContactsRepo interface {
	Insert(ctx context.Context, userPubKey, contactPubKey, contactAddr, contactName, contactNetwork string) error
	List(ctx context.Context, userPubKey string) ([]Contact, error)
	GetContactKeyInfo(ctx context.Context, userPubKey, contactAddr string) (ContactKeyInfo, error)
}

type EsiaLink struct {
	EsiaUserID string
	EthAddress string
	ChainID    uint64
}

type EsiaLinkRepo interface {
	SaveLink(ctx context.Context, esiaUserID, ethAddress string, chainID uint64) error
	GetByEsiaID(ctx context.Context, esiaUserID string) (EsiaLink, error)
}
