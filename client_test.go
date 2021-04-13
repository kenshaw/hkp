package hkp

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
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
	if hash := fmt.Sprintf("%x", md5.Sum(buf)); hash != "6ba146bef75ec72d419a2395b663039a" {
		t.Errorf("expected hash of key result %q to be %q, got: %q", id, "6ba146bef75ec72d419a2395b663039a", hash)
	}
}

func TestClientGetKeys(t *testing.T) {
	ids := []string{
		"4ED778F539E3634C779C87C6D7062848A1AB005C", // Beth Griggs <bgriggs@redhat.com>
		"94AE36675C464D64BAFA68DD7434390BDBE9B9C5", // Colin Ihrig <cjihrig@gmail.com>
		"74F12602B6F1C4E913FAA37AD3A89613643B6201", // Danielle Adams <adamzdanielle@gmail.com>
		"71DCFD284A79C3B38668286BC97EC7A07EDE3FC1", // James M Snell <jasnell@keybase.io>
		"8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600", // Michaël Zasso <targos@protonmail.com>
		"C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8", // Myles Borins <myles.borins@gmail.com>
		"C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C", // Richard Lau <rlau@redhat.com>
		"DD8F2338BAE7501E3DD5AC78C273792F7D83545D", // Rod Vagg <rod@vagg.org>
		"A48C2BEE680E841632CD4E44F07496B3EB3C1762", // Ruben Bridgewater <ruben@bridgewater.de>
		"108F52B48DB57BB0CC439B2997B01419BD92F80A", // Ruy Adorno <ruyadorno@hotmail.com>
		"B9E2F5981AA6E0CD28160D9FF13993A75599653C", // Shelley Vohr <shelley.vohr@gmail.com>
	}
	cl := New(WithSksKeyserversPool())
	buf, err := cl.GetKeys(context.Background(), ids...)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(keys) < len(ids) {
		t.Errorf("expected len(keys)<len(ids): %d<%d", len(keys), len(ids))
	}
}
