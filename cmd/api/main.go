package main

import (
	"log"
	"testMM/internal/app"
	"testMM/internal/config"

	"github.com/joho/godotenv"
)

func init() {
	// optional .env loading
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	application, err := app.Wire(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}

// func init() {
// 	// loads values from .env into the system
// 	if err := godotenv.Load(); err != nil {
// 		log.Print("No .env file found")
// 	}
// }

// func (s *Server) initDB(ctx context.Context) error {
// 	s.dbOnce.Do(func() {
// 		dsn := strings.TrimSpace(os.Getenv("PG_DSN"))
// 		if dsn == "" {
// 			s.dbErr = errors.New("PG_DSN env is required")
// 			return
// 		}

// 		pool, err := pgxpool.New(ctx, dsn)
// 		if err != nil {
// 			s.dbErr = err
// 			return
// 		}

// 		if err := pool.Ping(ctx); err != nil {
// 			pool.Close()
// 			s.dbErr = err
// 			return
// 		}

// 		s.db = pool
// 	})

// 	return s.dbErr
// }

// type Server struct {
// 	cfg config.Config

// 	rpcMu sync.RWMutex
// 	rpc   map[uint64]*ethclient.Client

// 	nonceMu sync.Mutex
// 	nonces  map[string]nonceEntry // key: addrLower + ":" + chainId

// 	sessMu sync.Mutex
// 	sess   map[[32]byte]refreshSession // key: sha256(refreshToken)

// 	dbOnce sync.Once
// 	db     *pgxpool.Pool
// 	dbErr  error
// }

// type nonceEntry struct {
// 	Nonce     string
// 	Domain    string
// 	URI       string
// 	ChainID   uint64
// 	ExpiresAt time.Time
// }

// type refreshSession struct {
// 	Address   string
// 	ChainID   uint64
// 	ExpiresAt time.Time
// 	CreatedAt time.Time
// 	LastUsed  time.Time
// }

// func main() {
// 	cfg, err := config.LoadConfig()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	s := &Server{
// 		cfg:    cfg,
// 		rpc:    make(map[uint64]*ethclient.Client),
// 		nonces: make(map[string]nonceEntry),
// 		sess:   make(map[[32]byte]refreshSession),
// 	}

// 	r := gin.New()
// 	r.Use(gin.Logger(), gin.Recovery())
// 	r.Use(s.corsMiddleware())

// 	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
// 	r.GET("/chains", s.handleChains)

// 	auth := r.Group("/auth")
// 	auth.POST("/siwe/init", s.handleSiweInit)
// 	auth.POST("/siwe/verify", s.handleSiweVerify)
// 	auth.POST("/refresh", s.handleRefresh)
// 	auth.POST("/logout", s.handleLogout)

// 	protected := r.Group("/")
// 	protected.Use(s.accessJWTMiddleware())
// 	protected.Use(s.dbMiddleware())

// 	protected.GET("/me", s.handleMe)
// 	protected.POST("/contacts", s.handleAddContact)
// 	protected.GET("/contacts", s.handleGetContacts)

// 	log.Printf("listening on %s", cfg.ListenAddr)
// 	if err := r.Run(cfg.ListenAddr); err != nil {
// 		log.Fatal(err)
// 	}
// }

// /* -------------------- CORS -------------------- */

// func (s *Server) corsMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		origin := c.Request.Header.Get("Origin")
// 		if origin != "" {
// 			// Если allowlist пустой — можно разрешить все (для демо),
// 			// но лучше всегда задавать ALLOWED_ORIGINS.
// 			if len(s.cfg.AllowedOrigin) == 0 {
// 				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
// 			} else {
// 				if _, ok := s.cfg.AllowedOrigin[origin]; ok {
// 					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
// 				}
// 			}
// 			c.Writer.Header().Set("Vary", "Origin")
// 			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
// 			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
// 		}

// 		if c.Request.Method == http.MethodOptions {
// 			c.AbortWithStatus(http.StatusNoContent)
// 			return
// 		}
// 		c.Next()
// 	}
// }

// /* -------------------- API: chains -------------------- */

// func (s *Server) handleChains(c *gin.Context) {
// 	out := make([]gin.H, 0, len(s.cfg.RPCByChainID))
// 	for chainID := range s.cfg.RPCByChainID {
// 		out = append(out, gin.H{"chainId": chainID})
// 	}
// 	c.JSON(200, gin.H{"chains": out})
// }

// /* -------------------- SIWE init/verify -------------------- */

// type siweInitReq struct {
// 	Address string `json:"address"`
// 	ChainID uint64 `json:"chainId"`
// }

// type siweInitResp struct {
// 	Nonce     string `json:"nonce"`
// 	Message   string `json:"message"`
// 	ExpiresAt string `json:"expiresAt"`
// 	Domain    string `json:"domain"`
// 	URI       string `json:"uri"`
// }

// func (s *Server) handleSiweInit(c *gin.Context) {
// 	var req siweInitReq
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(400, gin.H{"error": "bad json"})
// 		return
// 	}

// 	if !common.IsHexAddress(req.Address) {
// 		c.JSON(400, gin.H{"error": "invalid address"})
// 		return
// 	}
// 	if _, ok := s.cfg.RPCByChainID[req.ChainID]; !ok {
// 		c.JSON(400, gin.H{"error": "unsupported chainId"})
// 		return
// 	}

// 	// ✅ Берём domain+uri строго из Origin (это реальный сайт, где пользователь нажал "Sign")
// 	origin := strings.TrimSpace(c.GetHeader("Origin"))
// 	if origin == "" {
// 		c.JSON(400, gin.H{"error": "missing Origin header"})
// 		return
// 	}

// 	// ✅ Allowlist origin (защита от подмены)
// 	if len(s.cfg.AllowedOrigin) > 0 {
// 		if _, ok := s.cfg.AllowedOrigin[origin]; !ok {
// 			c.JSON(400, gin.H{"error": "origin not allowed"})
// 			return
// 		}
// 	}

// 	u, err := url.Parse(origin)
// 	if err != nil || u.Scheme == "" || u.Host == "" {
// 		c.JSON(400, gin.H{"error": "bad Origin"})
// 		return
// 	}

// 	domain := u.Host // например "localhost:5173" или "your.site"
// 	uri := origin    // например "http://localhost:5173"

// 	nonce, err := randomBase64URL(16)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "nonce gen failed"})
// 		return
// 	}

// 	now := time.Now().UTC()
// 	exp := now.Add(s.cfg.NonceTTL)

// 	statement := "Sign in to DemoApp"
// 	message := buildSIWEMessage(
// 		domain,
// 		common.HexToAddress(req.Address).Hex(),
// 		uri,
// 		statement,
// 		req.ChainID,
// 		nonce,
// 		now,
// 		exp,
// 	)

// 	key := nonceKey(req.Address, req.ChainID)

// 	s.nonceMu.Lock()
// 	s.nonces[key] = nonceEntry{
// 		Nonce:     nonce,
// 		Domain:    domain,
// 		URI:       uri,
// 		ChainID:   req.ChainID,
// 		ExpiresAt: exp,
// 	}
// 	s.nonceMu.Unlock()

// 	c.JSON(200, siweInitResp{
// 		Nonce:     nonce,
// 		Message:   message,
// 		ExpiresAt: exp.Format(time.RFC3339),
// 		Domain:    domain,
// 		URI:       uri,
// 	})
// }

// type siweVerifyReq struct {
// 	Message   string `json:"message"`
// 	Signature string `json:"signature"` // "0x..."
// }

// type siweVerifyResp struct {
// 	Address        string `json:"address"`
// 	ChainID        uint64 `json:"chainId"`
// 	AccessToken    string `json:"accessToken"`
// 	AccessExpires  string `json:"accessExpires"`
// 	RefreshToken   string `json:"refreshToken"`
// 	RefreshExpires string `json:"refreshExpires"`
// }

// func (s *Server) handleSiweVerify(c *gin.Context) {
// 	var req siweVerifyReq
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(400, gin.H{"error": "bad json"})
// 		return
// 	}

// 	msg, err := siwe.ParseMessage(req.Message)
// 	if err != nil {
// 		c.JSON(400, gin.H{"error": "invalid siwe message"})
// 		return
// 	}

// 	addr := msg.GetAddress() // common.Address
// 	chainID := uint64(msg.GetChainID())
// 	if _, ok := s.cfg.RPCByChainID[chainID]; !ok {
// 		c.JSON(400, gin.H{"error": "unsupported chainId"})
// 		return
// 	}

// 	key := nonceKey(addr.Hex(), chainID)

// 	s.nonceMu.Lock()
// 	entry, ok := s.nonces[key]
// 	s.nonceMu.Unlock()

// 	if !ok || time.Now().After(entry.ExpiresAt) {
// 		c.JSON(401, gin.H{"error": "nonce expired or not found"})
// 		return
// 	}

// 	// Доп. проверки на подмену контекста
// 	if entry.Domain != msg.GetDomain() {
// 		c.JSON(401, gin.H{"error": "domain mismatch"})
// 		return
// 	}

// 	uriURI := msg.GetURI()
// 	msgURI := uriURI.String()

// 	if normalizeURL(entry.URI) != normalizeURL(msgURI) {
// 		c.JSON(401, gin.H{"error": "uri mismatch"})
// 		return
// 	}

// 	if entry.ChainID != chainID {
// 		c.JSON(401, gin.H{"error": "chainId mismatch"})
// 		return
// 	}
// 	if entry.Nonce != msg.GetNonce() {
// 		c.JSON(401, gin.H{"error": "nonce mismatch"})
// 		return
// 	}

// 	// Verify: проверка подписи EIP-191 + time constraints + matching domain/nonce. :contentReference[oaicite:3]{index=3}
// 	d := entry.Domain
// 	n := entry.Nonce
// 	if _, err := msg.Verify(req.Signature, &d, &n, nil); err != nil {
// 		c.JSON(401, gin.H{"error": "invalid signature"})
// 		return
// 	}
// 	if err := s.initDB(c.Request.Context()); err != nil {
// 		c.JSON(500, gin.H{"error": "db init failed: " + err.Error()})
// 		return
// 	}

// 	// nonce одноразовый
// 	s.nonceMu.Lock()
// 	delete(s.nonces, key)
// 	s.nonceMu.Unlock()

// 	accessExp := time.Now().Add(s.cfg.AccessTTL)
// 	access, err := s.issueAccessJWT(addr.Hex(), chainID, accessExp)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "jwt issue failed"})
// 		return
// 	}

// 	refreshToken, refreshExp, err := s.issueRefresh(addr.Hex(), chainID)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "refresh issue failed"})
// 		return
// 	}

// 	c.JSON(200, siweVerifyResp{
// 		Address:        addr.Hex(),
// 		ChainID:        chainID,
// 		AccessToken:    access,
// 		AccessExpires:  accessExp.UTC().Format(time.RFC3339),
// 		RefreshToken:   refreshToken,
// 		RefreshExpires: refreshExp.UTC().Format(time.RFC3339),
// 	})
// }

// func normalizeURL(s string) string {
// 	s = strings.TrimSpace(s)
// 	s = strings.TrimRight(s, "/")
// 	return s
// }

// func (s *Server) dbMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		if err := s.initDB(c.Request.Context()); err != nil {
// 			c.AbortWithStatusJSON(500, gin.H{"error": "db init failed: " + err.Error()})
// 			return
// 		}
// 		c.Set("db", s.db)
// 		c.Next()
// 	}
// }

// type AddContactRequest struct {
// 	Name      string `json:"name" binding:"required"`
// 	Address   string `json:"address" binding:"required"`
// 	Network   string `json:"network" binding:"required"`
// 	PublicKey string `json:"public_key" binding:"required"`
// }

// func (s *Server) handleAddContact(c *gin.Context) {
// 	// JWT middleware уже положил "address"
// 	userAddr := c.MustGet("address").(common.Address).Hex() // это будет user_pub_key

// 	var req AddContactRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	// Если контакт — EVM адрес, проверим формат (опционально)
// 	if !common.IsHexAddress(req.Address) {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid contact address"})
// 		return
// 	}

// 	db := c.MustGet("db").(*pgxpool.Pool)

// 	_, err := db.Exec(
// 		c.Request.Context(),
// 		`insert into contacts (user_pub_key, contact_pub_key, contact_addr, contact_name, contact_network)
// 		 values ($1, $2, $3, $4, $5)`,
// 		strings.ToLower(userAddr),
// 		req.PublicKey,
// 		strings.ToLower(req.Address),
// 		req.Name,
// 		req.Network,
// 	)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"contact_addr": strings.ToLower(req.Address)})
// }

// type ContactDTO struct {
// 	PublicKey string `json:"public_key"`
// 	Address   string `json:"address"`
// 	Name      string `json:"name"`
// 	Network   string `json:"network"`
// }

// func (s *Server) handleGetContacts(c *gin.Context) {
// 	userAddr := c.MustGet("address").(common.Address).Hex() // user_pub_key
// 	db := c.MustGet("db").(*pgxpool.Pool)

// 	rows, err := db.Query(
// 		c.Request.Context(),
// 		`select contact_pub_key, contact_addr, contact_name, contact_network
// 		 from contacts
// 		 where user_pub_key = $1
// 		 order by contact_name asc`,
// 		strings.ToLower(userAddr),
// 	)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	defer rows.Close()

// 	contacts := make([]ContactDTO, 0)
// 	for rows.Next() {
// 		var it ContactDTO
// 		if err := rows.Scan(&it.PublicKey, &it.Address, &it.Name, &it.Network); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 			return
// 		}
// 		contacts = append(contacts, it)
// 	}
// 	if err := rows.Err(); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"contacts": contacts})
// }

// /* -------------------- Refresh rotation -------------------- */

// type refreshReq struct {
// 	RefreshToken string `json:"refreshToken"`
// }

// type refreshResp struct {
// 	AccessToken    string `json:"accessToken"`
// 	AccessExpires  string `json:"accessExpires"`
// 	RefreshToken   string `json:"refreshToken"`
// 	RefreshExpires string `json:"refreshExpires"`
// }

// func (s *Server) handleRefresh(c *gin.Context) {
// 	var req refreshReq
// 	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
// 		c.JSON(400, gin.H{"error": "bad json"})
// 		return
// 	}

// 	hash := sha256.Sum256([]byte(req.RefreshToken))

// 	s.sessMu.Lock()
// 	session, ok := s.sess[hash]
// 	if !ok || time.Now().After(session.ExpiresAt) {
// 		s.sessMu.Unlock()
// 		c.JSON(401, gin.H{"error": "invalid refresh token"})
// 		return
// 	}

// 	// rotation: удаляем старый refresh
// 	delete(s.sess, hash)
// 	s.sessMu.Unlock()

// 	accessExp := time.Now().Add(s.cfg.AccessTTL)
// 	access, err := s.issueAccessJWT(session.Address, session.ChainID, accessExp)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "jwt issue failed"})
// 		return
// 	}

// 	newRefresh, newRefreshExp, err := s.issueRefresh(session.Address, session.ChainID)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "refresh issue failed"})
// 		return
// 	}

// 	c.JSON(200, refreshResp{
// 		AccessToken:    access,
// 		AccessExpires:  accessExp.UTC().Format(time.RFC3339),
// 		RefreshToken:   newRefresh,
// 		RefreshExpires: newRefreshExp.UTC().Format(time.RFC3339),
// 	})
// }

// func (s *Server) handleLogout(c *gin.Context) {
// 	var req refreshReq
// 	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
// 		c.JSON(400, gin.H{"error": "bad json"})
// 		return
// 	}

// 	hash := sha256.Sum256([]byte(req.RefreshToken))

// 	s.sessMu.Lock()
// 	delete(s.sess, hash)
// 	s.sessMu.Unlock()

// 	c.JSON(200, gin.H{"ok": true})
// }

// func (s *Server) issueRefresh(address string, chainID uint64) (token string, exp time.Time, err error) {
// 	token, err = randomBase64URL(32)
// 	if err != nil {
// 		return "", time.Time{}, err
// 	}
// 	exp = time.Now().Add(s.cfg.RefreshTTL)

// 	hash := sha256.Sum256([]byte(token))

// 	s.sessMu.Lock()
// 	s.sess[hash] = refreshSession{
// 		Address:   address,
// 		ChainID:   chainID,
// 		ExpiresAt: exp,
// 		CreatedAt: time.Now(),
// 		LastUsed:  time.Now(),
// 	}
// 	s.sessMu.Unlock()

// 	return token, exp, nil
// }

// /* -------------------- Access JWT + middleware -------------------- */

// type AccessClaims struct {
// 	Typ     string `json:"typ"`      // "access"
// 	ChainID uint64 `json:"chain_id"` // selected network at login
// 	jwt.RegisteredClaims
// }

// func (s *Server) issueAccessJWT(address string, chainID uint64, exp time.Time) (string, error) {
// 	claims := AccessClaims{
// 		Typ:     "access",
// 		ChainID: chainID,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			Subject:   address,
// 			IssuedAt:  jwt.NewNumericDate(time.Now()),
// 			ExpiresAt: jwt.NewNumericDate(exp),
// 		},
// 	}
// 	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return tok.SignedString([]byte(s.cfg.AccessSecret))
// }

// func (s *Server) accessJWTMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		h := c.GetHeader("Authorization")
// 		if !strings.HasPrefix(h, "Bearer ") {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "missing bearer token"})
// 			return
// 		}
// 		raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))

// 		var claims AccessClaims
// 		parsed, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
// 			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
// 				return nil, errors.New("unexpected signing method")
// 			}
// 			return []byte(s.cfg.AccessSecret), nil
// 		})
// 		if err != nil || !parsed.Valid {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
// 			return
// 		}
// 		if claims.Typ != "access" {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token type"})
// 			return
// 		}
// 		if !common.IsHexAddress(claims.Subject) {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "invalid subject"})
// 			return
// 		}
// 		if _, ok := s.cfg.RPCByChainID[claims.ChainID]; !ok {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "unsupported chainId"})
// 			return
// 		}

// 		c.Set("address", common.HexToAddress(claims.Subject))
// 		c.Set("chainId", claims.ChainID)
// 		c.Next()
// 	}
// }

// /* -------------------- Protected: /me -------------------- */

// func (s *Server) handleMe(c *gin.Context) {
// 	addr := c.MustGet("address").(common.Address)
// 	chainID := c.MustGet("chainId").(uint64)

// 	rpc, err := s.rpcClient(chainID)
// 	if err != nil {
// 		c.JSON(502, gin.H{"error": "rpc unavailable"})
// 		return
// 	}

// 	wei, err := rpc.BalanceAt(c.Request.Context(), addr, nil)
// 	if err != nil {
// 		c.JSON(502, gin.H{"error": "rpc balance failed"})
// 		return
// 	}

// 	c.JSON(200, gin.H{
// 		"address": addr.Hex(),
// 		"chainId": chainID,
// 		"balance": weiToEthString(wei),
// 		"unit":    "ETH",
// 	})
// }

// func (s *Server) rpcClient(chainID uint64) (*ethclient.Client, error) {
// 	s.rpcMu.RLock()
// 	if c, ok := s.rpc[chainID]; ok {
// 		s.rpcMu.RUnlock()
// 		return c, nil
// 	}
// 	s.rpcMu.RUnlock()

// 	s.rpcMu.Lock()
// 	defer s.rpcMu.Unlock()

// 	if c, ok := s.rpc[chainID]; ok {
// 		return c, nil
// 	}

// 	url := s.cfg.RPCByChainID[chainID]
// 	client, err := ethclient.DialContext(context.Background(), url)
// 	if err != nil {
// 		return nil, err
// 	}
// 	s.rpc[chainID] = client
// 	return client, nil
// }

// /* -------------------- Helpers -------------------- */

// func buildSIWEMessage(domain, address, uri, statement string, chainID uint64, nonce string, issuedAt time.Time, expiration time.Time) string {
// 	// Формат по EIP-4361. :contentReference[oaicite:4]{index=4}
// 	return fmt.Sprintf(
// 		`%s wants you to sign in with your Ethereum account:
// %s

// %s

// URI: %s
// Version: 1
// Chain ID: %d
// Nonce: %s
// Issued At: %s
// Expiration Time: %s`,
// 		domain,
// 		address,
// 		statement,
// 		uri,
// 		chainID,
// 		nonce,
// 		issuedAt.UTC().Format(time.RFC3339),
// 		expiration.UTC().Format(time.RFC3339),
// 	)
// }

// func nonceKey(address string, chainID uint64) string {
// 	return strings.ToLower(strings.TrimSpace(address)) + ":" + strconv.FormatUint(chainID, 10)
// }

// func randomBase64URL(nBytes int) (string, error) {
// 	b := make([]byte, nBytes)
// 	if _, err := rand.Read(b); err != nil {
// 		return "", err
// 	}
// 	return base64.RawURLEncoding.EncodeToString(b), nil
// }

// func weiToEthString(wei *big.Int) string {
// 	rat := new(big.Rat).SetInt(wei)
// 	den := new(big.Rat).SetInt(big.NewInt(1_000_000_000_000_000_000))
// 	rat.Quo(rat, den)
// 	return rat.FloatString(18)
// }
