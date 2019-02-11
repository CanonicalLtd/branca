# branca

[![Build Status](https://travis-ci.org/CanonicalLtd/branca.svg?branch=master)](https://travis-ci.org/CanonicalLtd/branca) [![Go Report Card](https://goreportcard.com/badge/github.com/CanonicalLtd/branca)](https://goreportcard.com/report/github.com/CanonicalLtd/branca)
[![GoDoc](https://godoc.org/github.com/CanonicalLtd/branca?status.svg)](https://godoc.org/github.com/CanonicalLtd/branca) 

Branca is a secure alternative to JWT, This implementation is written in pure Go (no cgo dependencies) and implements the [branca token specification](https://github.com/tuupola/branca-spec).

It was originally forked from `github.com/hako/branca` and the API
and implementation fairly extensively modified. Specifically:

 - the token payload is now `[]byte` not `string`.
 - the client is responsible for checking timestamp expiry, which simplifies the API and makes it possible to use a different expiry duration based on the payload contents.
 - it's possible for external code to choose the nonce and timestamp, which is useful for tests.
 - the external basex dependency has been removed.
 - encoding a token no longer returns an error.
 - the base62 wrapping is now optional, making it efficient to fold a token into some other binary format without incurring double-encoding cost.
 - less work is done for each encoding and decoding (the encrypter and the base62 encoder are created only once)

# Requirements

Go 1.10 and beyond.

# Install

```
go get -u github.com/CanonicalLtd/branca
```

See [the godoc](https://godoc.org/github.com/CanonicalLtd/branca)
for examples and more information on the API.
