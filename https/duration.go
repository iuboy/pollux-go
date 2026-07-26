package https

import "time"

// Duration is a constructor helper that takes the address of a duration
// literal. It is the pointer-time.Duration equivalent of `&[]time.Duration{d}[0]`
// without the visual noise. Use it to populate ServerOptions/ClientOptions
// timeout fields:
//
//	opts := &ServerOptions{
//	    ReadTimeout:  Duration(30 * time.Second),
//	    WriteTimeout: Duration(30 * time.Second),
//	    IdleTimeout:  Duration(120 * time.Second),
//	}
//
// or with NoTimeout() to explicitly opt out of a timeout (nil leaves the
// package default in place, which is different from explicitly disabling).
func Duration(d time.Duration) *time.Duration {
	return &d
}

// NoTimeout returns a *time.Duration pointing at zero, which the
// ServerOptions/ClientOptions builders interpret as "explicitly no timeout".
// This is different from nil (apply package default) and from a non-zero
// duration (use that duration). Deployments that opt out of timeouts MUST be
// behind a reverse proxy that enforces its own timeouts — removing the
// server-side timeout disables Slowloris protection.
func NoTimeout() *time.Duration {
	d := time.Duration(0)
	return &d
}

// resolveTimeout normalizes a *time.Duration against a default. The semantics
// are:
//
//   - nil            → def (the caller-supplied default)
//   - non-nil zero   → 0 (explicitly no timeout)
//   - non-nil nonzero → the pointed-to duration
//
// This is the single source of truth for the *time.Duration resolution rules.
func resolveTimeout(t *time.Duration, def time.Duration) time.Duration {
	if t == nil {
		return def
	}
	return *t
}
