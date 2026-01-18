// internal/scan/scan.go
package scan

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	// метод, который фильтруем по selector (transferNFTToContract)
	TargetMethodSelectorHex = "0x6393badb"
)

// ABI Bridge: нужен transferNFTToContract + event TokenLocked (для log фильтра)
const bridgeABIJSON = `[
  {"anonymous":false,"inputs":[
    {"indexed":false,"internalType":"uint256","name":"tokenId","type":"uint256"},
    {"indexed":false,"internalType":"address","name":"sender","type":"address"},
    {"indexed":false,"internalType":"address","name":"addressInChainB","type":"address"},
    {"indexed":false,"internalType":"string","name":"tokenURIValue","type":"string"}
  ],"name":"TokenLocked","type":"event"},

  {"inputs":[
    {"internalType":"address","name":"_nftContract","type":"address"},
    {"internalType":"address","name":"ownerAddressInChainB","type":"address"},
    {"internalType":"uint256","name":"_tokenId","type":"uint256"}
  ],
  "name":"transferNFTToContract",
  "outputs":[{"internalType":"bool","name":"","type":"bool"}],
  "stateMutability":"nonpayable","type":"function"}
]`

// ERC721: только tokenURI (если понадобится fallback-колл)
const erc721URIABIJSON = `[
  {"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],
   "name":"tokenURI",
   "outputs":[{"internalType":"string","name":"","type":"string"}],
   "stateMutability":"view","type":"function"}
]`

type TxScanParams struct {
	NetworkKey string

	BridgeAddr common.Address

	// ✅ sender = тот, кто вызывает функцию (из JWT)
	Sender common.Address

	// ✅ contactAddr = recipient (фильтр по получателю)
	RecipientFilter common.Address

	FromBlock uint64 // 0 = auto
	ToBlock   uint64 // 0 = latest

	// optional override: если хочешь жёстко ограничить конкретным NFT контрактом
	NFTContract string
}

type ScanItem struct {
	TxHash      string `json:"txHash"`
	BlockNumber uint64 `json:"blockNumber"`

	TokenID   string `json:"tokenId"`
	Recipient string `json:"recipient"`

	TokenURI    string `json:"tokenURI"`
	CID         string `json:"cid"`
	Name        string `json:"name"`
	DownloadURL string `json:"downloadUrl"`

	Method string `json:"method"`
	Sender string `json:"sender"`

	Bridge      string `json:"bridge"`
	NFTContract string `json:"nftContract"`
}

type ScanResponse struct {
	Network     string     `json:"network"`
	BridgeAddr  string     `json:"bridgeAddr"`
	Method      string     `json:"method"`
	Sender      string     `json:"sender"`
	Recipient   string     `json:"recipient"`
	FromBlock   uint64     `json:"fromBlock"`
	ToBlock     uint64     `json:"toBlock"`
	Items       []ScanItem `json:"items"`
	LastBlock   uint64     `json:"lastBlock"`
	ItemsCount  int        `json:"itemsCount"`
	NFTContract string     `json:"nftContract"` // если был override/или найден в input
}

/* ---------------- RPC Provider ---------------- */

type RPCProvider interface {
	ClientForNetwork(networkKey string) (*ethclient.Client, error)
}

// Простой провайдер: networkKey -> rpcURL
type SimpleRPCProvider struct {
	RPCByNetwork map[string]string
}

func (p *SimpleRPCProvider) ClientForNetwork(networkKey string) (*ethclient.Client, error) {
	urls := strings.TrimSpace(p.RPCByNetwork[networkKey])
	if urls == "" {
		return nil, fmt.Errorf("rpc not configured for network: %s", networkKey)
	}
	return ethclient.Dial(urls)
}

/* ---------------- TxScanner ---------------- */

type TxScanner struct {
	rpc RPCProvider

	bridgeABI abi.ABI
	erc721ABI abi.ABI

	selector []byte
	evtID    common.Hash
}

func NewTxScanner(rpc RPCProvider) (*TxScanner, error) {
	bABI, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		return nil, fmt.Errorf("parse bridge abi: %w", err)
	}
	eABI, err := abi.JSON(strings.NewReader(erc721URIABIJSON))
	if err != nil {
		return nil, fmt.Errorf("parse erc721 abi: %w", err)
	}

	sel, err := hex.DecodeString(strings.TrimPrefix(TargetMethodSelectorHex, "0x"))
	if err != nil || len(sel) != 4 {
		return nil, fmt.Errorf("bad method selector: %s", TargetMethodSelectorHex)
	}

	evt := bABI.Events["TokenLocked"].ID

	return &TxScanner{
		rpc:       rpc,
		bridgeABI: bABI,
		erc721ABI: eABI,
		selector:  sel,
		evtID:     evt,
	}, nil
}

// Сканируем по логам TokenLocked на bridge, затем подтверждаем selector+sender по tx,
// получаем recipient из input/event, tokenId из event, tokenURI из event,
// дополнительно вытаскиваем _nftContract из input (если нужно).
func (s *TxScanner) ScanTransfers(ctx context.Context, p TxScanParams) (ScanResponse, error) {
	client, err := s.rpc.ClientForNetwork(p.NetworkKey)
	if err != nil {
		return ScanResponse{}, err
	}
	defer client.Close()

	latest, err := client.BlockNumber(ctx)
	if err != nil {
		return ScanResponse{}, fmt.Errorf("latest block: %w", err)
	}

	from, to := normalizeRange(p.FromBlock, p.ToBlock, latest)

	// optional override: если задан — будем фильтровать по нему (из input)
	var overrideNFT common.Address
	hasOverrideNFT := false
	if strings.TrimSpace(p.NFTContract) != "" {
		if !common.IsHexAddress(p.NFTContract) {
			return ScanResponse{}, fmt.Errorf("NFTContract override invalid: %s", p.NFTContract)
		}
		overrideNFT = common.HexToAddress(p.NFTContract)
		hasOverrideNFT = true
	}

	// 1) получаем логи TokenLocked от bridge
	q := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{p.BridgeAddr},
		Topics:    [][]common.Hash{{s.evtID}},
	}

	logs, err := client.FilterLogs(ctx, q)
	if err != nil {
		return ScanResponse{}, fmt.Errorf("FilterLogs: %w", err)
	}

	// chainId нужен для восстановления sender tx
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return ScanResponse{}, fmt.Errorf("chainId: %w", err)
	}
	signer := types.LatestSignerForChainID(chainID)

	type tokenLockedEvent struct {
		TokenId         *big.Int       `abi:"tokenId"`
		Sender          common.Address `abi:"sender"`
		AddressInChainB common.Address `abi:"addressInChainB"`
		TokenURIValue   string         `abi:"tokenURIValue"`
	}

	items := make([]ScanItem, 0)

	for _, lg := range logs {
		// 2) decode TokenLocked event (tokenId/sender/recipient/tokenURIValue)
		var ev tokenLockedEvent
		if err := s.bridgeABI.UnpackIntoInterface(&ev, "TokenLocked", lg.Data); err != nil {
			continue
		}

		// sender filter (event-level — быстрый отсев)
		if ev.Sender != p.Sender {
			continue
		}

		// recipient filter (contactAddr)
		if (p.RecipientFilter != common.Address{}) && ev.AddressInChainB != p.RecipientFilter {
			continue
		}

		// 3) достаем транзакцию и проверяем selector + sender(from) для надежности
		tx, _, err := client.TransactionByHash(ctx, lg.TxHash)
		if err != nil {
			continue
		}

		data := tx.Data()
		if len(data) < 4 || !bytesHasPrefix(data, s.selector) {
			continue
		}

		fromAddr, err := types.Sender(signer, tx)
		if err != nil {
			continue
		}
		if fromAddr != p.Sender {
			continue
		}

		// 4) decode input transferNFTToContract(...) чтобы получить nftContract + recipient + tokenId
		nftContractFromInput, recipientFromInput, tokenIDFromInput, err := decodeTransferInput(s.bridgeABI, data)
		if err != nil {
			continue
		}

		// recipient из input должен совпадать с event (иногда лучше доверять event)
		if recipientFromInput != ev.AddressInChainB {
			// не валим — но можно пропустить как "подозрительное"
			// continue
		}

		// tokenId из input должен совпадать с event
		if tokenIDFromInput != nil && ev.TokenId != nil && tokenIDFromInput.Cmp(ev.TokenId) != 0 {
			// continue
		}

		// optional override nft contract filter
		if hasOverrideNFT && nftContractFromInput != overrideNFT {
			continue
		}

		// 5) tokenURI берём из события (самое надёжное)
		tokenURI := strings.TrimSpace(ev.TokenURIValue)

		// fallback: если tokenURI пустой, пробуем tokenURI(tokenId) с nftContractFromInput
		if tokenURI == "" && ev.TokenId != nil {
			if uri2, err2 := callTokenURI(ctx, client, s.erc721ABI, nftContractFromInput, ev.TokenId); err2 == nil {
				tokenURI = strings.TrimSpace(uri2)
			}
		}

		// 6) parse name/cid
		name, cid := parseNameCid(tokenURI)
		if strings.TrimSpace(cid) == "" {
			// если tokenURI ipfs://CID...
			cid = extractCID(tokenURI)
		}

		// ✅ требование: если name отсутствует — заменить на URI
		if strings.TrimSpace(name) == "" {
			name = strings.TrimSpace(tokenURI)
		}
		if strings.TrimSpace(name) == "" {
			name = "document"
		}

		dl := tokenURIToHTTP(tokenURI)

		items = append(items, ScanItem{
			TxHash:      lg.TxHash.Hex(),
			BlockNumber: lg.BlockNumber,
			TokenID:     safeBigToString(ev.TokenId),
			Recipient:   ev.AddressInChainB.Hex(),
			TokenURI:    tokenURI,
			CID:         cid,
			Name:        name,
			DownloadURL: dl,
			Method:      TargetMethodSelectorHex,
			Sender:      p.Sender.Hex(),
			Bridge:      p.BridgeAddr.Hex(),
			NFTContract: nftContractFromInput.Hex(),
		})
	}

	// отсортируем от новых к старым
	sort.Slice(items, func(i, j int) bool {
		if items[i].BlockNumber == items[j].BlockNumber {
			return items[i].TxHash > items[j].TxHash
		}
		return items[i].BlockNumber > items[j].BlockNumber
	})

	resp := ScanResponse{
		Network:     p.NetworkKey,
		BridgeAddr:  p.BridgeAddr.Hex(),
		Method:      TargetMethodSelectorHex,
		Sender:      p.Sender.Hex(),
		Recipient:   p.RecipientFilter.Hex(),
		FromBlock:   from,
		ToBlock:     to,
		Items:       items,
		LastBlock:   latest,
		ItemsCount:  len(items),
		NFTContract: strings.TrimSpace(p.NFTContract),
	}

	return resp, nil
}

/* ---------------- helpers ---------------- */

func normalizeRange(from, to, latest uint64) (uint64, uint64) {
	if to == 0 {
		to = latest
	}

	if from == 0 {
		// дефолтное окно: env SCAN_WINDOW или 50k
		window := uint64(50_000)
		if w := strings.TrimSpace(os.Getenv("SCAN_WINDOW")); w != "" {
			if v, ok := parseUint(w); ok && v > 0 {
				window = v
			}
		}
		if to > window {
			from = to - window
		} else {
			from = 0
		}
	}

	if from > to {
		from, to = to, from
	}
	return from, to
}

func parseUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var v big.Int
	if _, ok := v.SetString(s, 10); ok {
		if v.Sign() < 0 {
			return 0, false
		}
		return v.Uint64(), true
	}
	return 0, false
}

func bytesHasPrefix(b, pref []byte) bool {
	if len(b) < len(pref) {
		return false
	}
	for i := range pref {
		if b[i] != pref[i] {
			return false
		}
	}
	return true
}

// decode calldata transferNFTToContract(address _nftContract, address ownerAddressInChainB, uint256 _tokenId)
func decodeTransferInput(a abi.ABI, data []byte) (nftContract common.Address, recipient common.Address, tokenID *big.Int, err error) {
	m, ok := a.Methods["transferNFTToContract"]
	if !ok {
		return common.Address{}, common.Address{}, nil, fmt.Errorf("method transferNFTToContract not found in ABI")
	}
	if len(data) < 4 {
		return common.Address{}, common.Address{}, nil, fmt.Errorf("bad input len")
	}

	args := map[string]interface{}{}
	if err := m.Inputs.UnpackIntoMap(args, data[4:]); err != nil {
		return common.Address{}, common.Address{}, nil, err
	}

	// types from abi unpack:
	// _nftContract -> common.Address
	// ownerAddressInChainB -> common.Address
	// _tokenId -> *big.Int
	nftContract = args["_nftContract"].(common.Address)
	recipient = args["ownerAddressInChainB"].(common.Address)
	tokenID = args["_tokenId"].(*big.Int)

	return nftContract, recipient, tokenID, nil
}

func callTokenURI(ctx context.Context, client *ethclient.Client, a abi.ABI, nft common.Address, tokenId *big.Int) (string, error) {
	data, err := a.Pack("tokenURI", tokenId)
	if err != nil {
		return "", err
	}

	msg := ethereum.CallMsg{To: &nft, Data: data}
	res, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return "", err
	}

	outs, err := a.Unpack("tokenURI", res)
	if err != nil || len(outs) == 0 {
		return "", err
	}

	return outs[0].(string), nil
}

// Поддержка tokenURI форматов:
// 1) JSON строка: {"name":"file.enc","cid":"bafy..."}
// 2) ipfs://CID?name=FILE (urlencoded)
// 3) "name=...;cid=..." / "cid=...|name=..."
func parseNameCid(tokenURI string) (name, cid string) {
	u := strings.TrimSpace(tokenURI)
	if u == "" {
		return "", ""
	}

	// 1) JSON
	if strings.HasPrefix(u, "{") && strings.HasSuffix(u, "}") {
		var m map[string]any
		if json.Unmarshal([]byte(u), &m) == nil {
			if v, ok := m["name"].(string); ok {
				name = strings.TrimSpace(v)
			}
			if v, ok := m["cid"].(string); ok {
				cid = strings.TrimSpace(v)
			}
			return
		}
	}

	// 2) ipfs://CID?...name=
	if strings.HasPrefix(u, "ipfs://") {
		rest := strings.TrimPrefix(u, "ipfs://")
		cidPart := rest
		q := ""

		if i := strings.Index(rest, "?"); i >= 0 {
			cidPart = rest[:i]
			q = rest[i+1:]
		} else if i := strings.Index(rest, "#"); i >= 0 {
			cidPart = rest[:i]
			q = rest[i+1:]
		}

		if cidPart != "" {
			cid = strings.TrimSpace(cidPart)
		}

		for _, kv := range strings.Split(q, "&") {
			kv = strings.TrimSpace(kv)
			if strings.HasPrefix(kv, "name=") {
				raw := strings.TrimPrefix(kv, "name=")
				if v, err := url.QueryUnescape(raw); err == nil {
					name = strings.TrimSpace(v)
				} else {
					name = strings.TrimSpace(raw)
				}
			}
			if strings.HasPrefix(kv, "cid=") {
				raw := strings.TrimPrefix(kv, "cid=")
				if v, err := url.QueryUnescape(raw); err == nil {
					cid = strings.TrimSpace(v)
				} else {
					cid = strings.TrimSpace(raw)
				}
			}
		}

		if name != "" || cid != "" {
			return
		}
	}

	// 3) name=... cid=...
	parts := strings.FieldsFunc(u, func(r rune) bool { return r == '|' || r == ';' || r == '&' })
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "name=") {
			raw := strings.TrimPrefix(part, "name=")
			if v, err := url.QueryUnescape(raw); err == nil {
				name = strings.TrimSpace(v)
			} else {
				name = strings.TrimSpace(raw)
			}
		}
		if strings.HasPrefix(part, "cid=") {
			raw := strings.TrimPrefix(part, "cid=")
			if v, err := url.QueryUnescape(raw); err == nil {
				cid = strings.TrimSpace(v)
			} else {
				cid = strings.TrimSpace(raw)
			}
		}
	}

	return
}

func extractCID(tokenURI string) string {
	u := strings.TrimSpace(tokenURI)
	if strings.HasPrefix(u, "ipfs://") {
		c := strings.TrimPrefix(u, "ipfs://")
		// remove query/fragment
		if i := strings.IndexAny(c, "?#"); i >= 0 {
			c = c[:i]
		}
		return strings.TrimSpace(c)
	}
	return ""
}

// ipfs://CID -> https://<gateway>/ipfs/CID (если задан PINATA_GATEWAY), иначе ipfs.io
func tokenURIToHTTP(tokenURI string) string {
	u := strings.TrimSpace(tokenURI)
	if strings.HasPrefix(u, "ipfs://") {
		cid := extractCID(u)
		if cid == "" {
			return "https://ipfs.io/ipfs/"
		}

		gw := strings.TrimSpace(os.Getenv("PINATA_GATEWAY"))
		if gw != "" {
			// PINATA_GATEWAY обычно вида: gateway.pinata.cloud или твой subdomain
			return "https://" + gw + "/ipfs/" + cid
		}
		return "https://ipfs.io/ipfs/" + cid
	}
	return u
}

func safeBigToString(x *big.Int) string {
	if x == nil {
		return ""
	}
	return x.String()
}
