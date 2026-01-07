package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr    string
	AccessSecret  string
	AccessTTL     time.Duration
	NonceTTL      time.Duration
	RefreshTTL    time.Duration
	AllowedOrigin map[string]struct{} // exact origins allowlist, e.g. http://localhost:5173
	RPCByChainID  map[uint64]string   // chainId -> rpc url

	PgDSN string
}

func LoadConfig() (Config, error) {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }

	cfg := Config{
		ListenAddr:    firstNonEmpty(get("LISTEN_ADDR"), ":8080"),
		AccessSecret:  get("JWT_ACCESS_SECRET"),
		AccessTTL:     parseDurationDefault(get("ACCESS_TTL"), 15*time.Minute),
		NonceTTL:      parseDurationDefault(get("NONCE_TTL"), 5*time.Minute),
		RefreshTTL:    parseDurationDefault(get("REFRESH_TTL"), 7*24*time.Hour),
		AllowedOrigin: make(map[string]struct{}),
		RPCByChainID:  make(map[uint64]string),

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
