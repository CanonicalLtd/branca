// Package branca implements the branca token specification.
//
// See https://github.com/tuupola/branca-spec for details.
//
// Although the standard specifies that tokens are base62-encoded,
// this package also provides access to the underlying data
// bytes so that they can be efficiently included in other
// byte-oriented formats.
package branca

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/CanonicalLtd/branca/internal/basex"
	"github.com/CanonicalLtd/branca/internal/fastuuid"
)

var (
	uuidGenOnce sync.Once
	uuidGen     = fastuuid.MustNewGenerator()
)

const (
	version byte = 0xBA // Branca magic byte
	base62       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	errInvalidToken        = errors.New("invalid base62 token")
	errInvalidTokenVersion = errors.New("invalid token version")
)

var base62Enc = func() *basex.Encoding {
	b, err := basex.NewEncoding(base62)
	if err != nil {
		panic(err)
	}
	return b
}()

// Base62 returns the base62 encoding of the given data,
// as specified by the Branca standard.
//
// By default, nonce values are generated
func Base62(data []byte) string {
	return base62Enc.Encode(data)
}

// Branca holds a key of exactly 32 bytes. The nonce and timestamp are used for acceptance tests.

// Branca encodes and decodes Branca tokens.
type Branca struct {
	encrypter cipher.AEAD
}

// New returns a new Codec that encodes and decodes
// Branca tokens with the given 256-bit key.
func New(key [32]byte) *Branca {
	encrypter, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	// By doing this lazily, there's probably better chance
	// that there's more entropy in the random number generator.
	uuidGenOnce.Do(func() {
		uuidGen = fastuuid.MustNewGenerator()
	})
	return &Branca{
		encrypter: encrypter,
	}
}

// EncodeToRawAtTime is like EncodeToRaw except that the created token
// will use the given timestamp and nonce.
//
// Note that the Base62 function can be used to convert the
// returned value to a valid Branca token.
func (b *Branca) EncodeToRawAtTime(payload []byte, nonce [24]byte, t time.Time) []byte {
	var timestamp uint32
	if !t.IsZero() {
		timestamp = uint32(t.Unix())
	}
	// version[1], timestamp[4], nonce[24], payload[N], auth[16]
	header := make([]byte, 1+4+24+len(payload)+16)
	header[0] = version
	binary.BigEndian.PutUint32(header[1:5], timestamp)
	copy(header[5:], nonce[:])
	return b.encrypter.Seal(header[0:1+4+24], nonce[:], payload, header[0:1+4+24])
}

// EncodeToRaw is like Encode except that it returns the underlying
// encoded token instead of returning it base62-encoded.
func (b *Branca) EncodeToRaw(payload []byte) []byte {
	return b.EncodeToRawAtTime(payload, uuidGen.Next(), time.Now())
}

// Encode encodes the given payload with the key that b was
// created with.
func (b *Branca) Encode(payload []byte) string {
	return Base62(b.EncodeToRaw(payload))
}

// DecodeRaw is like Decode except that it decodes a Branca token that
// is not base62 encoded.
func (b *Branca) DecodeRaw(data []byte) ([]byte, time.Time, error) {
	// version[1], timestamp[4], nonce[24], payload[N], auth[16]
	if len(data) < 1+4+24+16 {
		return nil, time.Time{}, errInvalidToken
	}
	header := data[0 : 1+4+24]
	payload, err := b.encrypter.Open(nil, header[1+4:1+4+24], data[1+4+24:], header)
	if err != nil {
		return nil, time.Time{}, err
	}
	if header[0] != version {
		return nil, time.Time{}, errInvalidTokenVersion
	}
	timestamp := int64(binary.BigEndian.Uint32(data[1 : 1+4]))
	var t time.Time
	if timestamp != 0 {
		t = time.Unix(timestamp, 0)
	}
	return payload, t, nil
}

// Decode decodes a Branca token. It returns the decrypted payload
// and the associated timestamp of the token.
func (b *Branca) Decode(token string) ([]byte, time.Time, error) {
	data, err := base62Enc.Decode(token)
	if err != nil {
		return nil, time.Time{}, errInvalidToken
	}
	return b.DecodeRaw(data)
}
