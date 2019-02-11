package branca_test

import (
	"crypto/sha256"
	"fmt"

	"github.com/CanonicalLtd/branca"
)

func ExampleEncode() {
	// Note that the key must be exactly 32 bytes long, so we
	// can hash an arbitrary length key to generate it.
	b := branca.New(sha256.Sum256([]byte("some key")))

	// Encode a string to a branca token.
	token := b.Encode([]byte("Hello world!"))
	fmt.Println(token)
}
