package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/ripemd160"
)

// HashCom 基础Hash组件
func HashCom(h hash.Hash, data []byte) []byte {
	_, err := h.Write(data)
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

// Sha256 s
func Sha256(data []byte) []byte {
	return HashCom(sha256.New(), data)
}

// Sha512 s
func Sha512(data []byte) []byte {
	return HashCom(sha512.New(), data)
}

// RipeMD160 s
func RipeMD160(data []byte) []byte {
	return HashCom(ripemd160.New(), data)
}

// HMACSHA512 s
func HMACSHA512(data, key []byte) []byte {
	hmac := hmac.New(sha512.New, key)
	return HashCom(hmac, data)
}

// HMACSHA256 s
func HMACSHA256(data, key []byte) []byte {
	hmac := hmac.New(sha256.New, key)
	return HashCom(hmac, data)
}
