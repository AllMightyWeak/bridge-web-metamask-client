package util

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
)

func RandomBase64URL(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func UintToString(v uint64) string {
	return strconv.FormatUint(v, 10)
}
