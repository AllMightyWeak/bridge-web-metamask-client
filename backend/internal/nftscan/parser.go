package nftscan

import (
	"fmt"
	"net/url"
	"strings"
)

func parseTokenURI(raw string) (cleanURI string, name string, cid string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		fmt.Println("error here: ", err)
		_, name, found := strings.Cut(raw, "?")
		if found {
			encodedName := strings.TrimPrefix(name, "name=")
			filename, err := url.QueryUnescape(encodedName)
			if err != nil {
				fmt.Println("Error decoding:", err)
				return "", "", ""
			}
			return raw, filename, ""
		}
		// если не распарсилось — вернем как есть
		return raw, "", ""
	}

	if u.Scheme == "ipfs" {
		// ipfs://CID  => Host = CID
		cid = strings.TrimSpace(u.Host)
		if cid != "" {
			cleanURI = "ipfs://" + cid
		} else {
			// на всякий случай: ipfs:// + path
			// (иногда кто-то пишет ipfs:/CID)
			p := strings.TrimPrefix(u.Path, "/")
			if p != "" {
				cid = p
				cleanURI = "ipfs://" + cid
			} else {
				cleanURI = raw
			}
		}

		name = strings.TrimSpace(u.Query().Get("name"))
		if name != "" {
			if decoded, err := url.QueryUnescape(name); err == nil {
				name = decoded
			}
		}
		return cleanURI, name, cid
	}

	// любой другой scheme — просто вернем raw
	name = strings.TrimSpace(u.Query().Get("name"))
	if name != "" {
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
	}
	return raw, name, ""
}
