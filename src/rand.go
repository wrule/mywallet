package main

import (
	"crypto/rand"
)

// RandGetN 获取随机字节切片
func RandGetN(size int) []byte {
	rst := make([]byte, size)
	n, err := rand.Read(rst)
	if err != nil {
		panic(err)
	}
	if n != size {
		panic("获取到的随机字节长度不符合期望")
	}
	return rst
}

// RandGetByte s
func RandGetByte() byte {
	return RandGetN(1)[0]
}

// RandGet32 s
func RandGet32() []byte {
	return RandGetN(32 / 8)
}

// RandGet64 s
func RandGet64() []byte {
	return RandGetN(64 / 8)
}

// RandGet128 s
func RandGet128() []byte {
	return RandGetN(128 / 8)
}

// RandGet256 s
func RandGet256() []byte {
	return RandGetN(256 / 8)
}

// RandGet512 s
func RandGet512() []byte {
	return RandGetN(512 / 8)
}

// RandGet1024 s
func RandGet1024() []byte {
	return RandGetN(1024 / 8)
}
