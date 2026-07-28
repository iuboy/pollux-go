package pwhash

// PasswordHasher is the uniform interface implemented by every password-hash
// scheme in this package.
//
// Hash encodes a password into a self-describing PHC-style string that
// embeds the algorithm name, parameters, salt, and derived digest. The same
// instance can hash with one set of parameters; verifying a hash encoded
// with different parameters reads those parameters back from the string.
//
// Verify returns true iff the password matches the encoded hash. It MUST be
// constant-time on the success/failure bit (the underlying primitives —
// argon2 and HMAC — already satisfy this) and MUST NOT leak the reason for
// failure.
//
// NeedsRehash reports whether an existing encoded hash should be recomputed
// with the current parameters — used to lazily upgrade hashes during login
// after a parameter bump or algorithm change.
type PasswordHasher interface {
	// Hash returns a PHC-style encoded string embedding algorithm + params.
	Hash(password string) (encoded string, err error)

	// Verify returns true iff password matches encoded.
	Verify(password, encoded string) bool

	// NeedsRehash returns true iff encoded was produced with different
	// parameters than this hasher's current ones (and should be rehashed).
	NeedsRehash(encoded string) bool

	// Algorithm returns the scheme identifier embedded at the start of every
	// encoded string this hasher produces (e.g. "argon2id", "pbkdf2-sm3").
	Algorithm() string
}
