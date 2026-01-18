package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type Config struct {
	ListenAddr    string
	AccessSecret  string
	AccessTTL     time.Duration
	NonceTTL      time.Duration
	RefreshTTL    time.Duration
	AllowedOrigin map[string]struct{} // exact origins allowlist, e.g. http://localhost:5173
	RPCByChainID  map[uint64]string   // chainId -> rpc url
	RPCByNetwork  map[string]string

	PgDSN           string
	BridgeByNetwork map[string]string

	WNFTRpcURL      string
	WNFTAddr        string
	NFTScanInterval time.Duration
}

func LoadConfig() (Config, error) {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }

	cfg := Config{
		ListenAddr:      firstNonEmpty(get("LISTEN_ADDR"), ":8080"),
		AccessSecret:    get("JWT_ACCESS_SECRET"),
		AccessTTL:       parseDurationDefault(get("ACCESS_TTL"), 15*time.Minute),
		NonceTTL:        parseDurationDefault(get("NONCE_TTL"), 5*time.Minute),
		RefreshTTL:      parseDurationDefault(get("REFRESH_TTL"), 7*24*time.Hour),
		AllowedOrigin:   make(map[string]struct{}),
		RPCByChainID:    make(map[uint64]string),
		RPCByNetwork:    make(map[string]string),
		WNFTRpcURL:      get("WNFT_RPC_URL"),
		WNFTAddr:        get("WNFT_ADDR"),
		NFTScanInterval: parseDurationDefault(get("NFT_SCAN_INTERVAL"), 15*time.Second),

		PgDSN: get("PG_DSN"),
	}

	if cfg.PgDSN == "" {
		return Config{}, errors.New("PG_DSN env is required")
	}

	if cfg.AccessSecret == "" {
		return Config{}, errors.New("JWT_ACCESS_SECRET env is required")
	}

	// ALLOWED_ORIGINS="http://localhost:5173,https://your.site"
	for _, o := range splitCSV(get("ALLOWED_ORIGINS")) {
		cfg.AllowedOrigin[o] = struct{}{}
	}

	// RPC_URLS="1=https://...;11155111=https://..."  (semicolon separated pairs)
	// пример: RPC_URLS="1=https://mainnet.infura.io/v3/XXX;11155111=https://sepolia.infura.io/v3/XXX"
	rpcs := get("RPC_URLS")
	if rpcs == "" {
		return Config{}, errors.New("RPC_URLS env is required (e.g. 1=https://...;11155111=https://...)")
	}
	for _, pair := range strings.Split(rpcs, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return Config{}, fmt.Errorf("bad RPC_URLS pair: %q", pair)
		}
		chainStr := strings.TrimSpace(kv[0])
		url := strings.TrimSpace(kv[1])
		chainID, err := strconv.ParseUint(chainStr, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("bad chain id %q: %w", chainStr, err)
		}
		if url == "" {
			return Config{}, fmt.Errorf("empty rpc url for chain %d", chainID)
		}
		cfg.RPCByChainID[chainID] = url
	}

	// BRIDGE_BY_NETWORK="sepolia=0x...;mainnet=0x..."
	bridges := get("BRIDGE_BY_NETWORK")
	cfg.BridgeByNetwork = make(map[string]string)
	for _, pair := range strings.Split(bridges, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return Config{}, fmt.Errorf("bad BRIDGE_BY_NETWORK pair: %q", pair)
		}
		net := strings.TrimSpace(kv[0])
		addr := strings.TrimSpace(kv[1])
		if net == "" || !common.IsHexAddress(addr) {
			return Config{}, fmt.Errorf("bad bridge mapping: %q", pair)
		}
		cfg.BridgeByNetwork[strings.ToLower(net)] = common.HexToAddress(addr).Hex()
	}

	rpcByNetwork, err := parseRPCByNetworkFromEnv()
	if err != nil {
		return cfg, err
	}
	cfg.RPCByNetwork = rpcByNetwork

	return cfg, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDurationDefault(s string, def time.Duration) time.Duration {
	if strings.TrimSpace(s) == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func parseRPCByNetworkFromEnv() (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv("RPC_BY_NETWORK"))
	if raw == "" {
		return map[string]string{}, nil
	}

	m := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("RPC_BY_NETWORK must be json object: %w", err)
	}

	// нормализуем ключи и чистим url
	out := make(map[string]string, len(m))
	for k, v := range m {
		kk := strings.ToLower(strings.TrimSpace(k))
		vv := strings.TrimSpace(v)
		if kk == "" || vv == "" {
			continue
		}
		out[kk] = vv
	}
	return out, nil
}
