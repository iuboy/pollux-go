package tls13gm

// TLS 1.3 key schedule label constants per RFC 8446 Section 7.1.
// These labels are used with HKDF-Expand-Label in the key derivation pipeline.
const (
	// LabelDerived is used to derive the next secret in the key schedule.
	LabelDerived = "derived"

	// LabelFinished is used for the Finished message verify_data.
	LabelFinished = "finished"

	// LabelResumption is used for the resumption PSK.
	LabelResumption = "resumption"

	// Traffic secret labels.
	LabelClientEarlyTraffic = "c e traffic"
	LabelClientHSTraffic   = "c hs traffic"
	LabelServerHSTraffic   = "s hs traffic"
	LabelClientAPTraffic   = "c ap traffic"
	LabelServerAPTraffic   = "s ap traffic"

	// Exporter label.
	LabelExporterMaster = "exp master"

	// Resumption master secret label.
	LabelResumptionMaster = "res master"

	// Key and IV derivation labels.
	LabelKey = "key"
	LabelIV  = "iv"
)
