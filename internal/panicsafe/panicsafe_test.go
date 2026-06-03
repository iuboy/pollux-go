package panicsafe

import (
	"errors"
	"strings"
	"testing"
)

func TestDo_Normal(t *testing.T) {
	err := Do(func() error {
		return errors.New("normal error")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "normal error" {
		t.Errorf("got %q, want %q", err.Error(), "normal error")
	}
}

func TestDo_NoError(t *testing.T) {
	err := Do(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestDo_Panic(t *testing.T) {
	err := Do(func() error {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if !strings.Contains(err.Error(), "pollux: unexpected error: boom") {
		t.Errorf("got %q, want prefix %q", err.Error(), "pollux: unexpected error: boom")
	}
	if !strings.Contains(err.Error(), "panicsafe") {
		t.Error("error should contain stack trace")
	}
}

func TestDo_PanicNil(t *testing.T) {
	err := Do(func() error {
		panic(nil)
	})
	if err == nil {
		t.Fatal("expected error from panic(nil)")
	}
}

func TestDo1_Normal(t *testing.T) {
	result, err := Do1(func() (string, error) {
		return "hello", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("got %q, want %q", result, "hello")
	}
}

func TestDo1_Error(t *testing.T) {
	result, err := Do1(func() (string, error) {
		return "", errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if result != "" {
		t.Errorf("expected zero value, got %q", result)
	}
}

func TestDo1_Panic(t *testing.T) {
	result, err := Do1(func() (int, error) {
		panic("crash")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if !strings.Contains(err.Error(), "pollux: unexpected error: crash") {
		t.Errorf("got %q", err.Error())
	}
	if result != 0 {
		t.Errorf("expected zero value, got %d", result)
	}
}

func TestDo2_Normal(t *testing.T) {
	r1, r2, err := Do2(func() (int, string, error) {
		return 42, "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r1 != 42 {
		t.Errorf("r1: got %d, want 42", r1)
	}
	if r2 != "ok" {
		t.Errorf("r2: got %q, want %q", r2, "ok")
	}
}

func TestDo2_Panic(t *testing.T) {
	r1, r2, err := Do2(func() (int, string, error) {
		panic("explode")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if !strings.Contains(err.Error(), "pollux: unexpected error: explode") {
		t.Errorf("got %q", err.Error())
	}
	if r1 != 0 {
		t.Errorf("expected zero r1, got %d", r1)
	}
	if r2 != "" {
		t.Errorf("expected zero r2, got %q", r2)
	}
}
