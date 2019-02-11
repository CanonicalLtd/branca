package branca

import (
	"encoding/hex"
	"testing"
	"time"
)

var testKey = func() (key [32]byte) {
	copy(key[:], []byte("supersecretkeyyoushouldnotcommit"))
	return
}()

// TestVector1 for testing encoding data to a valid branca token.
func TestVector1(t *testing.T) {
	tests := []struct {
		key       [32]byte
		nonce     string
		timestamp time.Time
		payload   string
		expected  string
	}{{
		key:       testKey,
		nonce:     "0102030405060708090a0b0c0102030405060708090a0b0c",
		timestamp: time.Unix(0, 0).Add(time.Second * 123206400),
		payload:   "Hello world!",
		expected:  "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a",
	}}

	for _, test := range tests {
		b := New(test.key)
		nonce := decodeHexNonce(test.nonce)
		// Encode token.
		encoded := b.EncodeToRawAtTime([]byte(test.payload), nonce, test.timestamp)
		encodedStr := Base62(encoded)
		if encodedStr != test.expected {
			t.Errorf("EncodeToString(%q) = %s. got %s, expected %q", test.payload, encoded, encoded, test.expected)
		}

		// Decode token..
		decoded, timestamp, err := b.Decode(encodedStr)
		if err != nil {
			t.Errorf("%q", err)
		}
		if string(decoded) != test.payload {
			t.Errorf("DecodeToString(%q) = %s. got %s, expected %q", test.expected, decoded, decoded, test.expected)
		}
		if !timestamp.Equal(test.timestamp) {
			t.Errorf("unexpected decoded timestamp; got %v want %v", timestamp, test.timestamp)
		}
	}
}

// TestInvalidDecodeString for testing errors when decoding branca tokens.
func TestInvalidDecodeString(t *testing.T) {
	tests := []struct {
		testName    string
		key         [32]byte
		token       string
		expectError string
	}{{
		testName:    "invalid-base62",
		key:         testKey,
		token:       "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a-",
		expectError: "invalid base62 token",
	}, {
		testName:    "invalid-key",
		key:         [32]byte{},
		token:       "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a",
		expectError: "chacha20poly1305: message authentication failed",
	}, {
		testName:    "data-too-short",
		token:       "875GH233T7IYrxtgXxlQBYiFo",
		expectError: "invalid base62 token",
	}}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			b := New(test.key)
			_, _, err := b.Decode(test.token)
			if err == nil {
				t.Fatalf("unexpected success")
			}
			if err.Error() != test.expectError {
				t.Fatalf("unexpected error; got %q want %q", err, test.expectError)
			}
		})
	}
}

func decodeHexNonce(s string) (nonce [24]byte) {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(data) != len(nonce) {
		panic("bad length")
	}
	copy(nonce[:], data)
	return
}
