package tls13gm

// TLS 1.3 key schedule label constants per RFC 8446 Section 7.1.
// These labels are used with HKDF-Expand-Label in the key derivation pipeline.
const (
	// LabelDerived is used to derive the next secret in the key schedule.
	LabelDerived = "derived"

	// LabelFinished is used for the Finished message verify_data.
	LabelFinished = "finished"

	// LabelResumption is the label for deriving the resumption PSK from the
	// resumption master secret: HKDF-Expand-Label(RMS, LabelResumption,
	// ticket_nonce, Hash.length). RFC 8446 §7.1 specifies "res psk", but
	// BabaSSL/Tongsuo — the standard GM peer for Route C — uses the non-standard
	// "resumption" label (verified at ssl/statem/statem_srvr.c:4260 in the
	// Tongsuo tree, source-level diagnosis). pollux adopts "resumption" for
	// interoperability; pollux <-> pollux stays consistent (both ends use it).
	LabelResumption = "resumption"

	// Traffic secret labels.
	LabelClientEarlyTraffic = "c e traffic"
	LabelClientHSTraffic    = "c hs traffic"
	LabelServerHSTraffic    = "s hs traffic"
	LabelClientAPTraffic    = "c ap traffic"
	LabelServerAPTraffic    = "s ap traffic"

	// Exporter label.
	LabelExporterMaster = "exp master"

	// Resumption master secret label.
	LabelResumptionMaster = "res master"

	// Binder key labels (RFC 8446 §7.1).
	LabelExternalBinder   = "ext binder"
	LabelResumptionBinder = "res binder"

	// Early exporter master secret label (RFC 8446 §7.1).
	LabelEarlyExporterMaster = "e exp master"

	// Key update label (RFC 8446 §7.2).
	LabelTrafficUpdate = "traffic upd"

	// Key and IV derivation labels.
	LabelKey = "key"
	LabelIV  = "iv"

	// QUIC packet protection labels per RFC 9001 §5.1.
	// These replace the TLS "key"/"iv" labels when a traffic secret is used to
	// protect QUIC packets rather than TLS 1.3 records.
	LabelQUICKey = "quic key"
	LabelQUICIV  = "quic iv"
	LabelQUICHP  = "quic hp"
	LabelQUICKU  = "quic ku"

	// QUIC Initial secret derivation labels per RFC 9001 §5.2.
	LabelQUICClientIn = "client in"
	LabelQUICServerIn = "server in"
)
