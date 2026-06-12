package test

import (
	"testing"

	polluxHTTP "github.com/iuboy/pollux-go/http"
)

func TestBlackBox_HTTP_DetectMode_NilCert(t *testing.T) {
	mode := polluxHTTP.DetectMode(nil)
	if mode != polluxHTTP.ModeTLS {
		t.Errorf("DetectMode(nil): got %v, want ModeTLS", mode)
	}
}

func TestBlackBox_HTTP_DetectMode_ExplicitMode(t *testing.T) {
	opts := &polluxHTTP.ServerOptions{Mode: polluxHTTP.ModeTLCP}
	if opts.DetectMode() != polluxHTTP.ModeTLCP {
		t.Error("explicit ModeTLCP should be returned")
	}

	opts2 := &polluxHTTP.ServerOptions{Mode: polluxHTTP.ModeTLS}
	if opts2.DetectMode() != polluxHTTP.ModeTLS {
		t.Error("explicit ModeTLS should be returned")
	}
}
