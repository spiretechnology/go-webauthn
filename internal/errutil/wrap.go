package errutil

import (
	"fmt"
)

func Wrap(err error) error {
	return fmt.Errorf("webauthn: %w", err)
}

func Wrapf(err error, format string, args ...any) error {
	return fmt.Errorf("webauthn: %s: %w", fmt.Sprintf(format, args...), err)
}
