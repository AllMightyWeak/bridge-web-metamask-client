package auth

import (
	"fmt"
	"time"
)

func BuildSIWEMessage(domain, address, uri, statement string, chainID uint64, nonce string, issuedAt time.Time, expiration time.Time) string {
	return fmt.Sprintf(
		`%s wants you to sign in with your Ethereum account:
%s

%s

URI: %s
Version: 1
Chain ID: %d
Nonce: %s
Issued At: %s
Expiration Time: %s`,
		domain,
		address,
		statement,
		uri,
		chainID,
		nonce,
		issuedAt.UTC().Format(time.RFC3339),
		expiration.UTC().Format(time.RFC3339),
	)
}
