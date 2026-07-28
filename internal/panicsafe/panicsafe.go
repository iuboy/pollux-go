// Package panicsafe converts unexpected panics into errors at public API boundaries.
package panicsafe

import (
	"fmt"
	"runtime/debug"
)

// panicPrefix is the error-message prefix for converted panics. Centralizing
// it as a constant keeps the three Do/Do1/Do2 wrappers in sync and lets a
// future rename or log-format change happen in one place.
const panicPrefix = "pollux: unexpected error"

// recoverAsError is the shared recover handler used by every Do* wrapper.
// Centralizing the recover logic avoids drift across the three variants
// (format, prefix, stack-trace inclusion). The named-error idiom (`err error`)
// plus `defer` lets the recovered value overwrite the wrapper's named return.
func recoverAsError(err *error, r any) {
	*err = fmt.Errorf("%s: %v\n%s", panicPrefix, r, debug.Stack())
}

// Do executes fn and converts any panic into an error with a stack trace.
func Do(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			recoverAsError(&err, r)
		}
	}()
	return fn()
}

// Do1 executes fn returning (T, error) and converts panics to errors.
func Do1[T any](fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			recoverAsError(&err, r)
		}
	}()
	return fn()
}

// Do2 executes fn returning (T1, T2, error) and converts panics to errors.
func Do2[T1, T2 any](fn func() (T1, T2, error)) (r1 T1, r2 T2, err error) {
	defer func() {
		if r := recover(); r != nil {
			recoverAsError(&err, r)
		}
	}()
	return fn()
}
