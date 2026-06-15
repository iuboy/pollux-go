package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/sm3"
)

// PSK key exchange modes (RFC 8446 §4.2.9). tls13gm uses psk_dhe_ke (PSK with
// (EC)DHE) for forward secrecy; pure psk_ke is not exercised.
const (
	PSKKeyExchangeModeKE    uint8 = 0 // psk_ke: PSK-only key establishment
	PSKKeyExchangeModeDHEKE uint8 = 1 // psk_dhe_ke: PSK with (EC)DHE
)

// PskIdentity is one entry of the pre_shared_key extension identities list:
// the opaque ticket (the resumption PSK in tls13gm) plus its obfuscated age.
type PskIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

// marshalPreSharedKeyExtension encodes the pre_shared_key extension value
// (RFC 8446 §4.2.11): an identities vector followed by a binders vector. Each
// binder is prefixed by a 1-byte length; each identity by a 2-byte length and a
// 4-byte obfuscated_ticket_age. Passing an empty/nil binders slice produces the
// truncated form used to compute the binder (the binders list length is 0).
func marshalPreSharedKeyExtension(identities []PskIdentity, binders [][]byte) ([]byte, error) {
	for _, id := range identities {
		if len(id.Identity) > 0xFFFF {
			return nil, fmt.Errorf("tls13gm: psk identity length %d exceeds 16 bits", len(id.Identity))
		}
	}
	idVec := make([]byte, 0, 16+len(identities)*len(identities))
	for _, id := range identities {
		idVec = append(idVec, byte(len(id.Identity)>>8), byte(len(id.Identity)))
		idVec = append(idVec, id.Identity...)
		idVec = append(idVec,
			byte(id.ObfuscatedTicketAge>>24),
			byte(id.ObfuscatedTicketAge>>16),
			byte(id.ObfuscatedTicketAge>>8),
			byte(id.ObfuscatedTicketAge))
	}
	binderVec := make([]byte, 0, 1+len(binders)*sm3.Size)
	for _, b := range binders {
		if len(b) > 0xFF {
			return nil, fmt.Errorf("tls13gm: psk binder length %d exceeds 8 bits", len(b))
		}
		binderVec = append(binderVec, byte(len(b)))
		binderVec = append(binderVec, b...)
	}
	out := make([]byte, 0, 4+len(idVec)+len(binderVec))
	out = append(out, byte(len(idVec)>>8), byte(len(idVec)))
	out = append(out, idVec...)
	out = append(out, byte(len(binderVec)>>8), byte(len(binderVec)))
	out = append(out, binderVec...)
	return out, nil
}

// parsePreSharedKeyExtension decodes the pre_shared_key extension value into
// identities and binders.
func parsePreSharedKeyExtension(data []byte) (identities []PskIdentity, binders [][]byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("tls13gm: pre_shared_key identities length truncated")
	}
	idLen := int(data[0])<<8 | int(data[1])
	p := 2
	if p+idLen > len(data) {
		return nil, nil, fmt.Errorf("tls13gm: pre_shared_key identities vector truncated")
	}
	idEnd := p + idLen
	for p < idEnd {
		if p+2 > idEnd {
			return nil, nil, fmt.Errorf("tls13gm: psk identity length truncated")
		}
		l := int(data[p])<<8 | int(data[p+1])
		p += 2
		if p+l+4 > idEnd {
			return nil, nil, fmt.Errorf("tls13gm: psk identity body truncated")
		}
		id := PskIdentity{Identity: append([]byte(nil), data[p:p+l]...)}
		p += l
		id.ObfuscatedTicketAge = uint32(data[p])<<24 | uint32(data[p+1])<<16 | uint32(data[p+2])<<8 | uint32(data[p+3])
		p += 4
		identities = append(identities, id)
	}
	if p+2 > len(data) {
		return nil, nil, fmt.Errorf("tls13gm: pre_shared_key binders length truncated")
	}
	binderLen := int(data[p])<<8 | int(data[p+1])
	p += 2
	if p+binderLen > len(data) {
		return nil, nil, fmt.Errorf("tls13gm: pre_shared_key binders vector truncated")
	}
	bEnd := p + binderLen
	for p < bEnd {
		if p+1 > bEnd {
			return nil, nil, fmt.Errorf("tls13gm: psk binder length truncated")
		}
		l := int(data[p])
		p++
		if p+l > bEnd {
			return nil, nil, fmt.Errorf("tls13gm: psk binder body truncated")
		}
		binders = append(binders, append([]byte(nil), data[p:p+l]...))
		p += l
	}
	return identities, binders, nil
}

// marshalPSKKeyExchangeModesExtension encodes the psk_key_exchange_modes
// extension value: a 1-byte list length followed by the selected modes.
func marshalPSKKeyExchangeModesExtension(modes []uint8) []byte {
	out := make([]byte, 0, 1+len(modes))
	out = append(out, byte(len(modes)))
	out = append(out, modes...)
	return out
}

// computeResumptionBinder computes the binder a client places in the
// pre_shared_key extension for a resumption PSK (RFC 8446 §4.2.11.2):
//
//	Early Secret    = HKDF-Extract(0, PSK)
//	binder_key      = DeriveSecret(Early Secret, "res binder", "")
//	finished_key    = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
//	binder          = HMAC(finished_key, Transcript-Hash(ClientHello_truncated))
//
// truncatedClientHello is the full handshake-message bytes (4-byte header +
// body) of the ClientHello carrying the pre_shared_key extension with an empty
// binders list.
func computeResumptionBinder(psk, truncatedClientHello []byte) ([]byte, error) {
	earlySecret := DeriveEarlySecret(psk)
	emptyHash := sm3.Sum(nil)
	binderKey, err := DeriveSecret(earlySecret, LabelResumptionBinder, emptyHash[:])
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive binder key: %w", err)
	}
	finishedKey, err := HKDFExpandLabel(binderKey, LabelFinished, nil, sm3.Size)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive binder finished key: %w", err)
	}
	chHash := sm3.Sum(truncatedClientHello)
	mac := sm3.NewHMAC(finishedKey)
	mac.Write(chHash[:])
	return mac.Sum(nil), nil
}
