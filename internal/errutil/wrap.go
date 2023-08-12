package errutil

import (
	"errors"
	"fmt"
)

func Newf(format string, args ...any) error {
	return Wrap(fmt.Errorf(format, args...))
}

func New(str string) error {
	return Wrap(errors.New(str))
}

func Wrap(err error) error {
	return fmt.Errorf("webauthn: %w", err)
}

func Wrapf(err error, format string, args ...any) error {
	return fmt.Errorf("webauthn: %s: %w", fmt.Sprintf(format, args...), err)
}
