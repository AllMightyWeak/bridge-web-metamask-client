package nftscan

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const erc721EnumerableABI = `[
  {
    "inputs":[{"internalType":"address","name":"owner","type":"address"}],
    "name":"balanceOf",
    "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
    "stateMutability":"view",
    "type":"function"
  },
  {
    "inputs":[
      {"internalType":"address","name":"owner","type":"address"},
      {"internalType":"uint256","name":"index","type":"uint256"}
    ],
    "name":"tokenOfOwnerByIndex",
    "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
    "stateMutability":"view",
    "type":"function"
  },
  {
    "inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],
    "name":"tokenURI",
    "outputs":[{"internalType":"string","name":"","type":"string"}],
    "stateMutability":"view",
    "type":"function"
  }
]`

type NFTItem struct {
	TokenID     string `json:"tokenId"`
	TokenURI    string `json:"tokenURI"` // оригинальная строка tokenURI (с ?name=)
	Name        string `json:"name"`     // имя файла (если нет — fallback на TokenURI)
	CID         string `json:"cid"`      // чистый CID
	DownloadURL string `json:"downloadUrl"`
}

type Scanner struct {
	client   *ethclient.Client
	abi      abi.ABI
	contract common.Address
}

func NewScanner(rpcURL, contractAddr string) (*Scanner, error) {
	c, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc: %w", err)
	}
	parsed, err := abi.JSON(strings.NewReader(erc721EnumerableABI))
	if err != nil {
		return nil, fmt.Errorf("parse abi: %w", err)
	}
	return &Scanner{
		client:   c,
		abi:      parsed,
		contract: common.HexToAddress(contractAddr),
	}, nil
}

// ВАЖНО: tokenURI вызываем по tokenId (не по i+1)
func (s *Scanner) ListByOwner(ctx context.Context, owner common.Address) ([]NFTItem, error) {
	bal, err := s.callBigInt1(ctx, "balanceOf", owner)
	if err != nil {
		return nil, err
	}

	n := bal.Int64()
	out := make([]NFTItem, 0, n)

	for i := int64(0); i < n; i++ {
		tokenId, err := s.callBigInt2(ctx, "tokenOfOwnerByIndex", owner, big.NewInt(i))
		if err != nil {
			return nil, err
		}

		uri, err := s.callString1(ctx, "tokenURI", tokenId)
		if err != nil {
			uri = "" // не валим весь список
		}

		cleanURI, name, cid := parseTokenURI(uri)

		// ✅ если name отсутствует — заменяем на URI (по требованию)
		if strings.TrimSpace(name) == "" {
			name = uri
		}

		out = append(out, NFTItem{
			TokenID:     tokenId.String(),
			TokenURI:    uri,
			Name:        name,
			CID:         cid,
			DownloadURL: ipfsCIDToHTTP(cid, cleanURI),
		})
	}

	return out, nil
}

func (s *Scanner) callBigInt1(ctx context.Context, method string, a1 any) (*big.Int, error) {
	data, err := s.abi.Pack(method, a1)
	if err != nil {
		return nil, err
	}
	msg := ethereum.CallMsg{To: &s.contract, Data: data}
	res, err := s.client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, err
	}
	outs, err := s.abi.Unpack(method, res)
	if err != nil || len(outs) == 0 {
		return nil, fmt.Errorf("%s unpack: %w", method, err)
	}
	return outs[0].(*big.Int), nil
}

func (s *Scanner) callBigInt2(ctx context.Context, method string, a1, a2 any) (*big.Int, error) {
	data, err := s.abi.Pack(method, a1, a2)
	if err != nil {
		return nil, err
	}
	msg := ethereum.CallMsg{To: &s.contract, Data: data}
	res, err := s.client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, err
	}
	outs, err := s.abi.Unpack(method, res)
	if err != nil || len(outs) == 0 {
		return nil, fmt.Errorf("%s unpack: %w", method, err)
	}
	return outs[0].(*big.Int), nil
}

func (s *Scanner) callString1(ctx context.Context, method string, a1 any) (string, error) {
	data, err := s.abi.Pack(method, a1)
	if err != nil {
		return "", err
	}
	msg := ethereum.CallMsg{To: &s.contract, Data: data}
	res, err := s.client.CallContract(ctx, msg, nil)
	if err != nil {
		return "", err
	}
	outs, err := s.abi.Unpack(method, res)
	if err != nil || len(outs) == 0 {
		return "", fmt.Errorf("%s unpack: %w", method, err)
	}
	return outs[0].(string), nil
}

/*
parseTokenURI поддерживает формат:

	ipfs://<cid>?name=<urlencoded>

Возвращает:

	cleanURI = ipfs://<cid> (без query)
	name     = decoded name (если есть)
	cid      = <cid>
*/

// Делает HTTP ссылку на CID. Если CID пустой — fallback на uri
func ipfsCIDToHTTP(cid string, uriFallback string) string {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return strings.TrimSpace(uriFallback)
	}

	// Если есть свой gateway — используем его
	if gw := strings.TrimSpace(os.Getenv("PINATA_GATEWAY")); gw != "" {
		return "https://" + gw + "/ipfs/" + cid
	}

	// дефолтный gateway
	return "https://ipfs.io/ipfs/" + cid
}

/* ---------- Watcher: хранит зарегистрированных пользователей и кэш NFT ---------- */

type Watcher struct {
	scanner  *Scanner
	interval time.Duration

	mu      sync.RWMutex
	users   map[string]common.Address // addrHexLower -> address
	cache   map[string][]NFTItem      // addrHexLower -> nfts
	lastErr map[string]string
}

func NewWatcher(scanner *Scanner, interval time.Duration) *Watcher {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Watcher{
		scanner:  scanner,
		interval: interval,
		users:    make(map[string]common.Address),
		cache:    make(map[string][]NFTItem),
		lastErr:  make(map[string]string),
	}
}

// Регистрируем пользователя (contactAddr) для скана.
// Вызывай при login/verify или при первом обращении к /nfts.
func (w *Watcher) Register(addr common.Address) {
	k := strings.ToLower(addr.Hex())
	w.mu.Lock()
	w.users[k] = addr
	w.mu.Unlock()
}

func (w *Watcher) GetCached(addr common.Address) ([]NFTItem, string) {
	k := strings.ToLower(addr.Hex())
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cache[k], w.lastErr[k]
}

func (w *Watcher) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(w.interval)
		defer t.Stop()

		for {
			w.scanOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (w *Watcher) scanOnce(parent context.Context) {
	// снимок списка пользователей
	w.mu.RLock()
	users := make([]common.Address, 0, len(w.users))
	for _, a := range w.users {
		users = append(users, a)
	}
	w.mu.RUnlock()

	for _, owner := range users {
		ctx, cancel := context.WithTimeout(parent, 12*time.Second)
		nfts, err := w.scanner.ListByOwner(ctx, owner)
		cancel()

		key := strings.ToLower(owner.Hex())

		w.mu.Lock()
		if err != nil {
			w.lastErr[key] = err.Error()
			w.mu.Unlock()
			log.Printf("[nftscan] owner=%s err=%v", owner.Hex(), err)
			continue
		}
		w.lastErr[key] = ""
		w.cache[key] = nfts
		w.mu.Unlock()
	}
}

func (w *Watcher) GetOrScanNow(parent context.Context, addr common.Address) ([]NFTItem, string) {
	// 1) если уже есть кэш — возвращаем
	items, errStr := w.GetCached(addr)
	if len(items) > 0 || errStr != "" {
		return items, errStr
	}

	// 2) если кэша нет — пробуем один раз быстро просканировать
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()

	nfts, err := w.scanner.ListByOwner(ctx, addr)
	key := strings.ToLower(addr.Hex())

	w.mu.Lock()
	defer w.mu.Unlock()

	if err != nil {
		w.lastErr[key] = err.Error()
		return nil, w.lastErr[key]
	}

	w.lastErr[key] = ""
	w.cache[key] = nfts
	return nfts, ""
}
