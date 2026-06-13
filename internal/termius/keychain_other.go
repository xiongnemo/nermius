//go:build !windows

package termius

import (
	"context"
	"errors"
)

type unsupportedLocalKeyReader struct{}

func defaultLocalKeyReader() LocalKeyReader {
	return unsupportedLocalKeyReader{}
}

func (unsupportedLocalKeyReader) ReadLocalKey(ctx context.Context) (string, error) {
	return "", errors.New("Termius local export is currently supported only on Windows; Linux and macOS localKey reading is not implemented yet")
}
