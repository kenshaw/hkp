package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kenshaw/hkp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: hkp <KEY ID>\n")
		os.Exit(1)
	}
	if err := run(context.Background(), os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, ids ...string) error {
	cl := hkp.New(hkp.WithSksKeyserversPool())
	buf, err := cl.GetKeys(ctx, ids...)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(buf)
	return err
}
