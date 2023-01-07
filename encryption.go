package main

import (
	"crypto/aes"
)

func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	block.Encrypt(encrypted, data)
	return encrypted, nil
}

func Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	block.Decrypt(decrypted, data)
	return decrypted, nil
}

func EnsureKey(key []byte) bool {
	if len(key) != 16 || len(key) != 24 || len(key) != 32 {
		return false
	}
	return true
}
