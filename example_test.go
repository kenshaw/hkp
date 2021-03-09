package hkp_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"log"
	"strings"

	"github.com/kenshaw/hkp"
	"golang.org/x/crypto/openpgp"
)

// ExampleGetKey shows retrieving a specified key id.
func ExampleGetKey() {
	id := "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
	buf, err := hkp.GetKey(context.Background(), id)
	if err != nil {
		log.Fatal(err)
	}
	hash := fmt.Sprintf("%x", md5.Sum(buf))
	fmt.Println("hash:", hash)
	// Output:
	// hash: 3bcdb54d08b620590eede913e1004cc2
}

func ExampleGetKey_verify() {
	id := "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
	buf, err := hkp.GetKey(context.Background(), id)
	if err != nil {
		log.Fatal(err)
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(buf))
	if err != nil {
		log.Fatal(err)
	}
	if len(keys) != 1 {
		log.Fatal("expected keys length to be 1")
	}
	fingerprint := fmt.Sprintf("%x\n", keys[0].PrimaryKey.Fingerprint)
	fmt.Println("fingerprint:", strings.ToUpper(fingerprint))
	// Output:
	// fingerprint: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
}
