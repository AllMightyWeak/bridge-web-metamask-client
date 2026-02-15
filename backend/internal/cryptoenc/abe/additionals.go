package encryptionAbe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ddulesov/gogost/gost3412128"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"golang.org/x/crypto/hkdf"
)

type encryptedDataDTO struct {
	Policy string        `json:"policy"`
	Cipher fameCipherDTO `json:"cipher"`
}

type fameCipherDTO struct {
	// bn256 элементы сериализуем как bytes (Marshal/Unmarshal)
	Ct0     [3][]byte     `json:"ct0"`
	Ct      [][][3][]byte `json:"ct"` // ct[i][j] -> []byte
	CtPrime []byte        `json:"ctPrime"`

	// MSP (матрица + маппинг)
	RowToAttrib []string   `json:"rowToAttrib"`
	Mat         [][]string `json:"mat"` // big.Int как string (десятичный)

	// Sym
	SymEnc []byte `json:"symEnc"`
	Nonce  []byte `json:"nonce"`
}

var (
	ErrNilCipher = errors.New("cipher is nil")
	ErrBadData   = errors.New("bad serialized data")
)

var (
	kdfSalt = []byte("your-app:fame-kuz-mgm:salt:v1")
	kdfInfo = []byte("your-app:fame-kuz-mgm:key:v1")
)

func aadFromMSP(msp *abe.MSP) []byte {
	h := sha256.New()
	h.Write([]byte("MSP\x00v1\x00"))

	h.Write([]byte("RowToAttrib\x00"))
	for _, a := range msp.RowToAttrib {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}

	h.Write([]byte("Mat\x00"))
	for i := 0; i < len(msp.Mat); i++ {
		for j := 0; j < len(msp.Mat[i]); j++ {
			h.Write(msp.Mat[i][j].Bytes())
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}

	// Dimensions (optional, avoids some edge ambiguities)
	var dims [8]byte
	binary.BigEndian.PutUint32(dims[0:4], uint32(len(msp.Mat)))
	if len(msp.Mat) > 0 {
		binary.BigEndian.PutUint32(dims[4:8], uint32(len(msp.Mat[0])))
	}
	h.Write([]byte("Dims\x00"))
	h.Write(dims[:])

	return h.Sum(nil)
}

func deriveKuzKeyFromGT(keyGtBytes []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, keyGtBytes, kdfSalt, kdfInfo)
	key := make([]byte, gost3412128.KeySize) // 32 bytes
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

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

func PrintPolicy(department, role int) {
	switch department {
	case 0:
		fmt.Println("Департамент: Юридический")
		switch role {
		case 0:
			fmt.Println("Роль: Начальник")
		case 1:
			fmt.Println("Роль: Юрист")
		}
	case 1:
		fmt.Println("Департамент: Информационные технологии")
		switch role {
		case 0:
			fmt.Println("Роль: Начальник")
		case 1:
			fmt.Println("Роль: Разработчик")
		}
	case 2:
		fmt.Println("Департамент: Продажи")
		switch role {
		case 0:
			fmt.Println("Роль: Начальник")
		case 1:
			fmt.Println("Роль: Маркетогол")
		}
	}
}

// MarshalEncryptedDataToString -> base64(JSON(dto))
func MarshalEncryptedDataToString(ed EncryptedData) (string, error) {
	if ed.Cipher == nil || ed.Cipher.Msp == nil || ed.Cipher.CtPrime == nil {
		return "", ErrNilCipher
	}

	dto := encryptedDataDTO{
		Policy: ed.Policy,
		Cipher: fameCipherDTO{
			CtPrime: ed.Cipher.CtPrime.Marshal(),
			SymEnc:  ed.Cipher.SymEnc,
			Nonce:   ed.Cipher.Nonce,
		},
	}

	// Ct0
	for i := 0; i < 3; i++ {
		if ed.Cipher.Ct0[i] == nil {
			return "", ErrBadData
		}
		dto.Cipher.Ct0[i] = ed.Cipher.Ct0[i].Marshal()
	}

	// Ct
	dto.Cipher.Ct = make([][][3][]byte, len(ed.Cipher.Ct))
	for i := 0; i < len(ed.Cipher.Ct); i++ {
		dto.Cipher.Ct[i] = make([][3][]byte, 1)
		var triple [3][]byte
		for j := 0; j < 3; j++ {
			if ed.Cipher.Ct[i][j] == nil {
				return "", ErrBadData
			}
			triple[j] = ed.Cipher.Ct[i][j].Marshal()
		}
		dto.Cipher.Ct[i][0] = triple
	}

	// MSP: RowToAttrib
	dto.Cipher.RowToAttrib = append([]string(nil), ed.Cipher.Msp.RowToAttrib...)

	// MSP: Mat big.Int -> string
	mat := make([][]string, len(ed.Cipher.Msp.Mat))
	for i := range ed.Cipher.Msp.Mat {
		row := make([]string, len(ed.Cipher.Msp.Mat[i]))
		for j := range ed.Cipher.Msp.Mat[i] {
			row[j] = ed.Cipher.Msp.Mat[i][j].String()
		}
		mat[i] = row
	}
	dto.Cipher.Mat = mat

	raw, err := json.Marshal(dto)
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(raw), nil
}

// UnmarshalEncryptedDataFromString <- base64(JSON(dto))
func UnmarshalEncryptedDataFromString(s string) (EncryptedData, error) {
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return EncryptedData{}, err
	}

	var dto encryptedDataDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return EncryptedData{}, err
	}

	// rebuild MSP
	preMat := make([]data.Vector, len(dto.Cipher.Mat))
	for i := range dto.Cipher.Mat {
		vec := make(data.Vector, len(dto.Cipher.Mat[i]))
		for j := range dto.Cipher.Mat[i] {
			// Parse big.Int from string
			vec[j] = new(big.Int)
			if _, ok := vec[j].SetString(dto.Cipher.Mat[i][j], 10); !ok {
				return EncryptedData{}, ErrBadData
			}
		}
		preMat[i] = vec
	}
	matForMSP, err := data.NewMatrix(preMat)
	if err != nil {
		return EncryptedData{}, err
	}

	msp := &abe.MSP{
		Mat:         matForMSP,
		RowToAttrib: append([]string(nil), dto.Cipher.RowToAttrib...),
	}

	// rebuild cipher
	c := &FAMECipher{
		Msp:    msp,
		SymEnc: dto.Cipher.SymEnc,
		Nonce:  dto.Cipher.Nonce,
	}

	// CtPrime
	c.CtPrime = new(bn256.GT)
	if _, err := c.CtPrime.Unmarshal(dto.Cipher.CtPrime); err != nil {
		return EncryptedData{}, err
	}

	// Ct0
	for i := 0; i < 3; i++ {
		g2 := new(bn256.G2)
		if _, err := g2.Unmarshal(dto.Cipher.Ct0[i]); err != nil {
			return EncryptedData{}, err
		}
		c.Ct0[i] = g2
	}

	// Ct
	c.Ct = make([][3]*bn256.G1, len(dto.Cipher.Ct))
	for i := 0; i < len(dto.Cipher.Ct); i++ {
		// мы хранили как ct[i][0][j]
		tripleBytes := dto.Cipher.Ct[i][0]
		var triple [3]*bn256.G1
		for j := 0; j < 3; j++ {
			g1 := new(bn256.G1)
			if _, err := g1.Unmarshal(tripleBytes[j]); err != nil {
				return EncryptedData{}, err
			}
			triple[j] = g1
		}
		c.Ct[i] = triple
	}

	return EncryptedData{
		Cipher: c,
		Policy: dto.Policy,
	}, nil
}
