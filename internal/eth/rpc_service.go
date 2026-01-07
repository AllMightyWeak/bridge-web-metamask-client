package eth

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type RPCService struct {
	urls    map[uint64]string
	mu      sync.RWMutex
	clients map[uint64]*ethclient.Client
}

func NewRPCService(urls map[uint64]string) *RPCService {
	return &RPCService{urls: urls, clients: make(map[uint64]*ethclient.Client)}
}

func (s *RPCService) Client(chainID uint64) (*ethclient.Client, error) {
	s.mu.RLock()
	if c, ok := s.clients[chainID]; ok {
		s.mu.RUnlock()
		return c, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if c, ok := s.clients[chainID]; ok {
		return c, nil
	}

	url, ok := s.urls[chainID]
	if !ok || url == "" {
		return nil, errors.New("unsupported chainId")
	}
	c, err := ethclient.DialContext(context.Background(), url)
	if err != nil {
		return nil, err
	}
	s.clients[chainID] = c
	return c, nil
}

func (s *RPCService) BalanceWei(ctx context.Context, chainID uint64, addr common.Address) (*big.Int, error) {
	c, err := s.Client(chainID)
	if err != nil {
		return nil, err
	}
	return c.BalanceAt(ctx, addr, nil)
}
