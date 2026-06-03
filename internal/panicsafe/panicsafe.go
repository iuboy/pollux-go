// Package panicsafe converts unexpected panics into errors at public API boundaries.
package panicsafe

import (
	"fmt"
	"runtime/debug"
)

// Do executes fn and converts any panic into an error with a stack trace.
func Do(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pollux: unexpected error: %v\n%s", r, debug.Stack())
		}
	}()
	return fn()
}

// Do1 executes fn returning (T, error) and converts panics to errors.
func Do1[T any](fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pollux: unexpected error: %v\n%s", r, debug.Stack())
		}
	}()
	return fn()
}

// Do2 executes fn returning (T1, T2, error) and converts panics to errors.
func Do2[T1, T2 any](fn func() (T1, T2, error)) (r1 T1, r2 T2, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pollux: unexpected error: %v\n%s", r, debug.Stack())
		}
	}()
	return fn()
}
