package gost

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"log"

	"github.com/ddulesov/gogost/gost3412128"
	"github.com/ddulesov/gogost/mgm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/hkdf"
)

type CipherData struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	// Aad        []byte `json:"aad"`
	Filename string
}

type KuznichikPriv struct {
	*ecies.PrivateKey
}

var (
	errBadPackedCipherData = errors.New("bad packed cipher data")
)

const (
	kzMagicV2 = uint32(0x4B5A4332) // "KZC2"
	kzVerV2   = byte(2)
	kzHdrSzV2 = 4 + 1 + 4 + 2 + 4 + 2 // 17 bytes
	maxKeyLen = 512
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

func mgmNonce(n int) []byte {
	b := randBytes(n)
	b[0] &= 0x7F
	return b
}

// returns ciphertext, nonce, aad

// deriveKuzKey256HKDF выводит 32-байтный (256-битный) ключ Кузнечика из ECDH секрета z.
// s1 используем как salt, s2 как info (или наоборот — главное, чтобы на decrypt было так же).
func deriveKuzKey256HKDF(h func() hash.Hash, z, s1, s2 []byte) ([]byte, error) {
	r := hkdf.New(h, z, s1, s2)

	key := make([]byte, gost3412128.KeySize) // 32 bytes
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func Encrypt(rand io.Reader, pub *ecies.PublicKey, m, s1, s2 []byte, filename string) ([]byte, error) {
	params, err := pubkeyParams(pub)
	if err != nil {
		return nil, err
	}

	R, err := ecies.GenerateKey(rand, pub.Curve, params)
	if err != nil {
		return nil, err
	}

	z, err := R.GenerateShared(pub, params.KeyLen, params.KeyLen)
	if err != nil {
		return nil, err
	}

	hash := params.Hash()
	Ke, Km := deriveKeys(hash, z, s1, params.KeyLen)
	kuzKe, err := deriveKuzKey256HKDF(params.Hash, Ke, s1, s2)
	if err != nil {
		return nil, err
	}

	em, nonce, err := encryptKuznechik(m, kuzKe, filename)
	if err != nil {
		log.Println("error encrypting message: ", err)
	}

	d := messageTag(params.Hash, Km, em, s2)

	if curve, ok := pub.Curve.(crypto.EllipticCurve); ok {
		Rb := curve.Marshal(R.PublicKey.X, R.PublicKey.Y)
		ct := make([]byte, len(Rb)+len(em)+len(d))
		copy(ct, Rb)
		copy(ct[len(Rb):], em)
		copy(ct[len(Rb)+len(em):], d)

		dataBytes := PackCipherData(CipherData{Ciphertext: ct, Nonce: nonce, Filename: filename})
		return dataBytes, nil
	}
	return nil, ecies.ErrInvalidCurve
}

func encryptKuznechik(plaintext, key []byte, filename string) ([]byte, []byte, error) {
	block := gost3412128.NewCipher(key)

	aead, err := mgm.NewMGM(block, 16)
	if err != nil {
		return nil, nil, err
	}

	nonce := mgmNonce(aead.NonceSize())

	aad := []byte(filename)

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nonce, err
}

func (prv *KuznichikPriv) Decrypt(dataBytes []byte, s1, s2 []byte) (m []byte, err error) {
	var cipherData CipherData
	cipherData, err = UnpackCipherData(dataBytes)
	// err = json.Unmarshal(dataBytes, &cipherData)
	if err != nil {
		log.Println("error unmarshaling cipherdata: ", err)
	}

	if len(cipherData.Ciphertext) == 0 {
		return nil, ecies.ErrInvalidMessage
	}
	params, err := pubkeyParams(&prv.PublicKey)
	if err != nil {
		return nil, err
	}

	hash := params.Hash()

	var (
		rLen   int
		hLen   int = hash.Size()
		mStart int
		mEnd   int
	)

	switch cipherData.Ciphertext[0] {
	case 2, 3, 4:
		rLen = (prv.PublicKey.Curve.Params().BitSize + 7) / 4
		if len(cipherData.Ciphertext) < (rLen + hLen + 1) {
			return nil, ecies.ErrInvalidMessage
		}
	default:
		return nil, ecies.ErrInvalidPublicKey
	}

	mStart = rLen
	mEnd = len(cipherData.Ciphertext) - hLen

	R := new(ecies.PublicKey)
	R.Curve = prv.PublicKey.Curve

	if curve, ok := R.Curve.(crypto.EllipticCurve); ok {
		R.X, R.Y = curve.Unmarshal(cipherData.Ciphertext[:rLen])
		if R.X == nil {
			return nil, ecies.ErrInvalidPublicKey
		}

		z, err := prv.GenerateShared(R, params.KeyLen, params.KeyLen)
		if err != nil {
			return nil, err
		}
		Ke, Km := deriveKeys(hash, z, s1, params.KeyLen)

		d := messageTag(params.Hash, Km, cipherData.Ciphertext[mStart:mEnd], s2)
		if subtle.ConstantTimeCompare(cipherData.Ciphertext[mEnd:], d) != 1 {
			return nil, ecies.ErrInvalidMessage
		}
		kuzKe, err := deriveKuzKey256HKDF(params.Hash, Ke, s1, s2)
		if err != nil {
			return nil, err
		}
		dec, err := decryptKuznechik(kuzKe, cipherData.Ciphertext[mStart:mEnd], cipherData.Nonce, cipherData.Filename)
		if err != nil {
			log.Println("error decrypting message: ", err)
		}
		return dec, nil
	}
	return nil, ecies.ErrInvalidCurve
}

func decryptKuznechik(key, ciphertext, nonce []byte, filename string) ([]byte, error) {
	block := gost3412128.NewCipher(key)

	aead, err := mgm.NewMGM(block, 16)
	if err != nil {
		return nil, err
	}
	aad := []byte(filename)
	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(decrypted))
	return decrypted, nil
}

func pubkeyParams(key *ecies.PublicKey) (*ecies.ECIESParams, error) {
	params := key.Params
	if params == nil {
		if params = ecies.ParamsFromCurve(key.Curve); params == nil {
			return nil, ecies.ErrUnsupportedECIESParameters
		}
	}
	if params.KeyLen > maxKeyLen {
		return nil, ecies.ErrInvalidKeyLen
	}
	return params, nil
}

func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) []byte {
	counterBytes := make([]byte, 4)
	k := make([]byte, 0, roundup(kdLen, hash.Size()))
	for counter := uint32(1); len(k) < kdLen; counter++ {
		binary.BigEndian.PutUint32(counterBytes, counter)
		hash.Reset()
		hash.Write(counterBytes)
		hash.Write(z)
		hash.Write(s1)
		k = hash.Sum(k)
	}
	return k[:kdLen]
}

// roundup rounds size up to the next multiple of blocksize.
func roundup(size, blocksize int) int {
	return size + blocksize - (size % blocksize)
}

// deriveKeys creates the encryption and MAC keys using concatKDF.
func deriveKeys(hash hash.Hash, z, s1 []byte, keyLen int) (Ke, Km []byte) {
	K := concatKDF(hash, z, s1, 2*keyLen)
	Ke = K[:keyLen]
	Km = K[keyLen:]
	hash.Reset()
	hash.Write(Km)
	Km = hash.Sum(Km[:0])
	return Ke, Km
}

func messageTag(hash func() hash.Hash, km, msg, shared []byte) []byte {
	mac := hmac.New(hash, km)
	mac.Write(msg)
	mac.Write(shared)
	tag := mac.Sum(nil)
	return tag
}

func PackCipherData(cd CipherData) []byte {
	ctLen := len(cd.Ciphertext)
	nonceLen := len(cd.Nonce)
	// aadLen := len(cd.Aad)
	nameBytes := []byte(cd.Filename)
	nameLen := len(nameBytes)

	// Ограничение из-за uint16
	if nameLen > 0xFFFF {
		// Можно panic, можно обрезать, можно возвращать ошибку.
		// Тут сделаем безопасное обрезание, чтобы функция всегда возвращала []byte.
		nameBytes = nameBytes[:0xFFFF]
		nameLen = 0xFFFF
	}

	out := make([]byte, kzHdrSzV2+ctLen+nonceLen+nameLen)

	// header
	binary.BigEndian.PutUint32(out[0:4], kzMagicV2)
	out[4] = kzVerV2
	binary.BigEndian.PutUint32(out[5:9], uint32(ctLen))
	binary.BigEndian.PutUint16(out[9:11], uint16(nonceLen))
	// binary.BigEndian.PutUint32(out[11:15], uint32(aadLen))
	binary.BigEndian.PutUint16(out[11:13], uint16(nameLen))

	// payload
	off := kzHdrSzV2
	copy(out[off:off+ctLen], cd.Ciphertext)
	off += ctLen
	copy(out[off:off+nonceLen], cd.Nonce)
	off += nonceLen
	// copy(out[off:off+aadLen], cd.Aad)
	// off += aadLen
	copy(out[off:off+nameLen], nameBytes)

	return out
}

func UnpackCipherData(b []byte) (CipherData, error) {
	if len(b) < kzHdrSzV2 {
		return CipherData{}, errBadPackedCipherData
	}
	if binary.BigEndian.Uint32(b[0:4]) != kzMagicV2 || b[4] != kzVerV2 {
		return CipherData{}, errBadPackedCipherData
	}

	ctLen := int(binary.BigEndian.Uint32(b[5:9]))
	nonceLen := int(binary.BigEndian.Uint16(b[9:11]))
	// aadLen := int(binary.BigEndian.Uint32(b[11:15]))
	nameLen := int(binary.BigEndian.Uint16(b[11:13]))

	if ctLen < 0 || nonceLen < 0 || nameLen < 0 {
		return CipherData{}, errBadPackedCipherData
	}

	total := kzHdrSzV2 + ctLen + nonceLen + nameLen
	if total != len(b) {
		return CipherData{}, errBadPackedCipherData
	}

	off := kzHdrSzV2
	ct := b[off : off+ctLen]
	off += ctLen
	nonce := b[off : off+nonceLen]
	off += nonceLen
	// aad := b[off : off+aadLen]
	// off += aadLen
	filename := string(b[off : off+nameLen])

	// Важно: Ciphertext/Nonce/Aad — слайсы, ссылающиеся на исходный буфер b.
	return CipherData{
		Ciphertext: ct,
		Nonce:      nonce,
		// Aad:        aad,
		Filename: filename,
	}, nil
}
