package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

// HMACSHA512 s
func HMACSHA512(data, key []byte) []byte {
	hmac := hmac.New(sha512.New, key)
	_, err := hmac.Write(data)
	if err != nil {
		panic(err)
	}
	return hmac.Sum(nil)
}

// HMACSHA256 s
func HMACSHA256(data, key []byte) []byte {
	hmac := hmac.New(sha256.New, key)
	_, err := hmac.Write(data)
	if err != nil {
		panic(err)
	}
	return hmac.Sum(nil)
}
