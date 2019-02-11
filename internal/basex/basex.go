// Package basex provides fast base encoding / decoding of any given alphabet using bitcoin style leading zero compression.
// It is a GO port of https://github.com/cryptocoinjs/base-x
//
// It has been copied from github.com/eknkc/basex
// to avoid that external dependency, and updated somewhat
// for efficiency.
package basex

import (
	"errors"
	"strings"
)

// Encoding is a custom base encoding defined by an alphabet.
// It should bre created using NewEncoding function
type Encoding struct {
	base     int
	alphabet string
	// alphabetMap holds a mapping from alphabet character (index into alphabetMap)
	// to 1 + digit encoded by that alphabet character.
	alphabetMap [128]byte
	zero        byte
}

// NewEncoding returns a custom base encoder defined by the alphabet string.
// The alphabet should contain non-repeating characters.
// It does not allow non-ASCII characters in the alphabet.
// Ordering is important.
// Example alphabets:
//   - base2: 01
//   - base16: 0123456789abcdef
//   - base32: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
//   - base62: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
func NewEncoding(alphabet string) (*Encoding, error) {
	if len(alphabet) == 0 {
		return nil, errors.New("empty alphabet")
	}
	if len(alphabet) > 128 {
		return nil, errors.New("alphabet too large")
	}
	e := &Encoding{
		base:     len(alphabet),
		alphabet: alphabet,
		zero:     alphabet[0],
	}
	for i := 0; i < len(alphabet); i++ {
		b := alphabet[i]
		if b >= 128 {
			return nil, errors.New("out of range alphabet character")
		}
		if e.alphabetMap[b] > 0 {
			return nil, errors.New("duplicate character found in alphabet")
		}
		e.alphabetMap[b] = byte(i) + 1
	}
	return e, nil
}

// Encode function receives a byte slice and encodes it to a string using the alphabet provided
func (e *Encoding) Encode(source []byte) string {
	if len(source) == 0 {
		return ""
	}

	digits := []int{0}
	for i := 0; i < len(source); i++ {
		carry := int(source[i])
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % e.base
			carry = carry / e.base
		}
		for carry > 0 {
			digits = append(digits, carry%e.base)
			carry = carry / e.base
		}
	}

	var res strings.Builder
	for k := 0; source[k] == 0 && k < len(source)-1; k++ {
		res.WriteByte(e.zero)
	}
	for q := len(digits) - 1; q >= 0; q-- {
		res.WriteByte(e.alphabet[digits[q]])
	}

	return res.String()
}

// Decode function decodes a string previously obtained from Encode, using the same alphabet and returns a byte slice
// In case the input is not valid an arror will be returned
func (e *Encoding) Decode(source string) ([]byte, error) {
	if len(source) == 0 {
		return []byte{}, nil
	}

	bytes := []byte{0}
	for i := 0; i < len(source); i++ {
		c := source[i]
		if int(c) >= len(e.alphabetMap) {
			return nil, errors.New("unexpected character found")
		}
		value := int(e.alphabetMap[c])
		if value == 0 {
			return nil, errors.New("unexpected character found")
		}
		value--

		for j := 0; j < len(bytes); j++ {
			value += int(bytes[j]) * e.base
			bytes[j] = byte(value & 0xff)
			value >>= 8
		}

		for value > 0 {
			bytes = append(bytes, byte(value&0xff))
			value >>= 8
		}
	}

	for k := 0; source[k] == e.zero && k < len(source)-1; k++ {
		bytes = append(bytes, 0)
	}

	// Reverse bytes
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return bytes, nil
}
