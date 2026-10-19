package handshake

// gm_retry_test.go locks M7 (third security review): ChangeConnectionID
// re-derives the Initial keys from the Retry's new destination connection ID
// (RFC 9001 §5.2), so a GM client hitting a Retry-sending server protects its
// post-Retry Initial packets correctly instead of timing out.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

func TestGMCryptoSetup_ChangeConnectionID(t *testing.T) {
	origID := protocol.ParseConnectionID([]byte{0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98})
	retryID := protocol.ParseConnectionID([]byte{0xA9, 0xB8, 0xC7, 0xD6, 0xE5, 0xF4, 0x03, 0x12})
	tp := &wire.TransportParameters{MaxIdleTimeout: 10 * time.Second, ActiveConnectionIDLimit: 2}

	client, err := NewGMCryptoSetupClient(origID, &tls13gm.ClientConfig{
		InsecureSkipVerify: true,
		NextProtos:         []string{"echo"},
	}, tp, utils.DefaultLogger, protocol.Version1, nil)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupClient: %v", err)
	}
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}
	drainGMEvents(client)

	ad := []byte("retry-ad")
	payload := []byte("initial-crypto-frame")

	// Sanity: pre-Retry sealing uses the ORIGINAL DCID's keys.
	sealer, err := client.GetInitialSealer()
	if err != nil {
		t.Fatalf("GetInitialSealer: %v", err)
	}
	_ = sealer.Seal(nil, payload, 1, ad)

	// The Retry arrives: the client switches to the new DCID.
	client.ChangeConnectionID(retryID)

	// Post-Retry ciphertext must decrypt under the NEW DCID's independently
	// derived keys (this is exactly what the Retry-sending server does).
	newSealer, err := client.GetInitialSealer()
	if err != nil {
		t.Fatalf("GetInitialSealer (post-Retry): %v", err)
	}
	ct := newSealer.Seal(nil, payload, 2, ad)
	// The client seals with ClientInitialKeys; the server opens with the same
	// (DeriveQUICInitialSecrets' FIRST return seeds the client direction).
	clientIn, _, err := tls13gm.DeriveQUICInitialSecrets(retryID.Bytes())
	if err != nil {
		t.Fatalf("DeriveQUICInitialSecrets(retryID): %v", err)
	}
	newKeys, err := tls13gm.DeriveQUICPacketKeys(clientIn)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	newOpener, err := newGMLongOpener(newKeys)
	if err != nil {
		t.Fatalf("newGMLongOpener: %v", err)
	}
	pt, err := newOpener.Open(nil, ct, 2, ad)
	if err != nil {
		t.Fatalf("post-Retry ciphertext must open under the new DCID keys: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("post-Retry payload mismatch: %q", pt)
	}

	// And it must NOT decrypt under the ORIGINAL DCID's keys (proving the
	// keys actually changed rather than the old codecs being kept).
	oldClientIn, _, err := tls13gm.DeriveQUICInitialSecrets(origID.Bytes())
	if err != nil {
		t.Fatalf("DeriveQUICInitialSecrets(origID): %v", err)
	}
	oldKeys, err := tls13gm.DeriveQUICPacketKeys(oldClientIn)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys(old): %v", err)
	}
	oldOpener, err := newGMLongOpener(oldKeys)
	if err != nil {
		t.Fatalf("newGMLongOpener(old): %v", err)
	}
	if _, err := oldOpener.Open(nil, ct, 2, ad); err == nil {
		t.Fatal("post-Retry ciphertext opened under the OLD DCID keys — ChangeConnectionID did not re-derive")
	}

	// The client can also open server Initial data sealed with the new keys
	// (the server's post-Retry Initial packets).
	newOpenerClient, err := client.GetInitialOpener()
	if err != nil {
		t.Fatalf("GetInitialOpener: %v", err)
	}
	_, newServerIn, _ := tls13gm.DeriveQUICInitialSecrets(retryID.Bytes())
	srvKeys, err := tls13gm.DeriveQUICPacketKeys(newServerIn)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys(srv): %v", err)
	}
	srvSealer, err := newGMLongSealer(srvKeys)
	if err != nil {
		t.Fatalf("newGMLongSealer(srv): %v", err)
	}
	srvCT := srvSealer.Seal(nil, []byte("server-initial"), 1, ad)
	if pt, err := newOpenerClient.Open(nil, srvCT, 1, ad); err != nil || !bytes.Equal(pt, []byte("server-initial")) {
		t.Fatalf("client must open server post-Retry Initial data: %v", err)
	}
}
