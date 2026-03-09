package nftscan

import (
	"net/url"
	"strings"
)

func parseTokenURI(raw string) (cleanURI string, name string, cid string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}

	// ✅ 1) СНАЧАЛА достаем query руками (это работает даже для ABE-строк)
	// Берем часть после ПЕРВОГО '?' (или можно после ПОСЛЕДНЕГО, если боишься '?' внутри шифртекста)
	// Обычно у тебя '?name=' добавляется в конце, так что безопаснее брать ПОСЛЕДНИЙ '?'
	if i := strings.LastIndex(raw, "?"); i >= 0 && i+1 < len(raw) {
		q := raw[i+1:]
		for _, kv := range strings.Split(q, "&") {
			kv = strings.TrimSpace(kv)
			if strings.HasPrefix(kv, "name=") {
				v := strings.TrimPrefix(kv, "name=")
				if dec, err := url.QueryUnescape(v); err == nil {
					name = strings.TrimSpace(dec)
				} else {
					name = strings.TrimSpace(v)
				}
			}
			if strings.HasPrefix(kv, "cid=") {
				cid = strings.TrimSpace(strings.TrimPrefix(kv, "cid="))
			}
		}
	}

	// ✅ 2) Достаем cid/cleanURI из ipfs://CID (даже если дальше query)
	// cut off query/fragment
	base := raw
	if j := strings.IndexAny(base, "?#"); j >= 0 {
		base = base[:j]
	}

	if strings.HasPrefix(base, "ipfs://") {
		rest := strings.TrimPrefix(base, "ipfs://")
		rest = strings.TrimPrefix(rest, "/") // на всякий случай
		if rest != "" {
			// CID может быть до следующего '/'
			if k := strings.Index(rest, "/"); k >= 0 {
				cid = firstNonEmpty(cid, rest[:k])
			} else {
				cid = firstNonEmpty(cid, rest)
			}
			cleanURI = "ipfs://" + cid
		} else {
			cleanURI = raw
		}
		return cleanURI, name, cid
	}

	// 3) Если не ipfs://, то cleanURI не трогаем
	// (для ABE tokenURI это будет зашифрованная строка)
	return raw, name, cid
}

func firstNonEmpty(a, b string) string {
	a = strings.TrimSpace(a)
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}
