package cryptoenc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// EncryptMessage is taken from provided code (minimal adaptations).
func EncryptMessage(keyAny any, message []byte) []byte {
	var publicKeyECIES *ecies.PublicKey

	switch key := keyAny.(type) {
	case []byte:
		pub, err := crypto.UnmarshalPubkey(key)
		if err != nil {
			log.Println("err UnmarshalPubkey:", err)
			return nil
		}
		publicKeyECIES = ecies.ImportECDSAPublic(pub)
	case *ecies.PublicKey:
		publicKeyECIES = key
	case *ecdsa.PublicKey:
		publicKeyECIES = ecies.ImportECDSAPublic(key)
	default:
		log.Println("unsupported key type")
		return nil
	}

	ciphertext, err := ecies.Encrypt(rand.Reader, publicKeyECIES, message, nil, nil)
	if err != nil {
		log.Println("err Encrypt:", err)
		return nil
	}

	return ciphertext
}

func EncryptBytes(publicKeyECDSA *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	ct := EncryptMessage(publicKeyECDSA, plaintext)
	if ct == nil {
		return nil, ErrEncryptFailed
	}
	return ct, nil
}
