package handlers

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// GET /auth/esia/login
// Редирект на страницу ЕСИА
func (h *Handlers) EsiaLogin(c *gin.Context) {
	if h.Esia == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "ЕСИА не сконфигурирована",
		})
		return
	}

	authURL, _, err := h.Esia.AuthURL()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "esia auth url: " + err.Error()})
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

// GET /auth/esia/callback?code=...&state=...
// ЕСИА редиректит сюда. Мы обмениваем code → esiaUserID,
// затем редиректим браузер на фронт с esiaUserID в параметре.
func (h *Handlers) EsiaCallback(c *gin.Context) {
	if h.Esia == nil {
		c.Redirect(http.StatusFound, h.frontendURL("/?esia_error="+url.QueryEscape("ЕСИА не сконфигурирована")))
		return
	}

	query := c.Request.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	// Если ЕСИА вернула ошибку (пользователь отказал и т.п.)
	if esiaErr := query.Get("error"); esiaErr != "" {
		desc := query.Get("error_description")
		c.Redirect(http.StatusFound, h.frontendURL("/?esia_error="+url.QueryEscape(desc)))
		return
	}

	if code == "" || state == "" {
		c.Redirect(http.StatusFound, h.frontendURL("/?esia_error="+url.QueryEscape("отсутствует code или state")))
		return
	}

	oid, err := h.Esia.ExchangeCode(code, state)
	if err != nil {
		c.Redirect(http.StatusFound, h.frontendURL("/?esia_error="+url.QueryEscape(err.Error())))
		return
	}

	// Успех — редиректим на фронт с OID в параметре
	// Фронт прочитает esia_user_id из URL и перейдёт к экрану привязки кошелька
	c.Redirect(http.StatusFound, h.frontendURL("/?esia_user_id="+url.QueryEscape(oid)))
}

// frontendURL строит URL фронтенда.
// Берём origin из ESIA_REDIRECT_URI (там задан адрес фронта: http://localhost:3000/)
func (h *Handlers) frontendURL(path string) string {
	u, err := url.Parse(h.Cfg.EsiaRedirectURI)
	if err != nil || u.Host == "" {
		return path
	}
	return u.Scheme + "://" + u.Host + path
}
