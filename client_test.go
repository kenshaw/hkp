package hkp

import (
	"context"
	"crypto/md5"
	"fmt"
	"strings"
	"testing"
)

func TestClientGetKey_keyNotFound(t *testing.T) {
	id := strings.Repeat("a", 40)
	cl := New()
	_, err := cl.GetKey(context.Background(), id)
	if err != ErrKeyNotFound {
		t.Errorf("key %q expected key not found error, got: %v", id, err)
	}
}

func TestClientGetKey_validKey(t *testing.T) {
	id := "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
	cl := New()
	buf, err := cl.GetKey(context.Background(), id)
	if err != nil {
		t.Fatalf("key %q expected no error, got: %v", id, err)
	}
	if hash := fmt.Sprintf("%x", md5.Sum(buf)); hash != "3bcdb54d08b620590eede913e1004cc2" {
		t.Errorf("expected hash of key result %q to be %q, got: %q", id, "3bcdb54d08b620590eede913e1004cc2", hash)
	}
}
