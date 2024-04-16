package clipboard

import (
	"errors"

	nativeclipboard "github.com/aymanbagabas/go-nativeclipboard"
)

type Adapter interface {
	Available() bool
	ReadText() (string, error)
	WriteText(string) error
}

type NativeAdapter struct{}

func New() Adapter {
	return NativeAdapter{}
}

func (NativeAdapter) Available() bool {
	_, err := nativeclipboard.Text.Read()
	return err == nil
}

func (NativeAdapter) ReadText() (string, error) {
	data, err := nativeclipboard.Text.Read()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (NativeAdapter) WriteText(value string) error {
	_, err := nativeclipboard.Text.Write([]byte(value))
	if err != nil {
		return err
	}
	return nil
}

func IsUnavailable(err error) bool {
	return errors.Is(err, nativeclipboard.ErrUnavailable) || errors.Is(err, nativeclipboard.ErrUnsupported)
}
