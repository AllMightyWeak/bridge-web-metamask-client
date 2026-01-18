package ipfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

type UploadResponse struct {
	Data struct {
		Id        string `json:"id"`
		Name      string `json:"name"`
		Cid       string `json:"cid"`
		Size      int    `json:"size"`
		CreatedAt string `json:"created_at"`
		MimeType  string `json:"mime_type"`
		Network   string `json:"network"`
	} `json:"data"`
}

type Client struct {
	URL     string
	JWT     string
	Network string
	Timeout time.Duration
}

func NewFromEnv() (*Client, error) {
	url := os.Getenv("PINATA_URL")
	jwt := os.Getenv("PINATA_JWT")
	if url == "" || jwt == "" {
		return nil, errors.New("PINATA_URL and PINATA_JWT env are required")
	}
	return &Client{
		URL:     url,
		JWT:     jwt,
		Network: "public",
		Timeout: 60 * time.Second,
	}, nil
}

// UploadBytes uploads raw bytes as a "file" to Pinata (pinFileToIPFS).
func (c *Client) UploadBytes(filename string, data []byte) (UploadResponse, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return UploadResponse{}, err
	}
	if _, err := io.Copy(part, bytes.NewReader(data)); err != nil {
		return UploadResponse{}, err
	}

	if err := writer.WriteField("network", c.Network); err != nil {
		return UploadResponse{}, err
	}
	if err := writer.WriteField("name", filename); err != nil {
		return UploadResponse{}, err
	}
	if err := writer.Close(); err != nil {
		return UploadResponse{}, err
	}

	req, err := http.NewRequest("POST", c.URL, body)
	if err != nil {
		return UploadResponse{}, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.JWT)

	httpClient := &http.Client{Timeout: c.Timeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return UploadResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return UploadResponse{}, fmt.Errorf("pinata returned %d: %s", resp.StatusCode, string(b))
	}

	var out UploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return UploadResponse{}, err
	}
	return out, nil
}
