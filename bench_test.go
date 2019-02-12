package branca

import (
	"crypto/sha256"
	"testing"
)

func BenchmarkEncode(b *testing.B) {

	br := New(sha256.Sum256([]byte("key")))
	data := []byte("hello")
	for i := 0; i < b.N; i++ {
		br.Encode(data)
	}
}

func BenchmarkDecode(b *testing.B) {
	br := New(sha256.Sum256([]byte("key")))
	token := br.Encode([]byte("hello"))
	for i := 0; i < b.N; i++ {
		_, _, err := br.Decode(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}
