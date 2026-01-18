package handlers

import (
	"errors"
	"io"
)

var ErrFileTooLarge = errors.New("file too large")

func ioReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: limit + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrFileTooLarge
	}
	return b, nil
}
