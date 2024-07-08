package main

import (
	"crypto/aes"
	"crypto/cipher"
	//"crypto/rand"
	"crypto/sha256"
	"fmt"
	//"io"
	"os"
	"strconv"
	"strings"

	"github.com/enceve/crypto/pad"
	"golang.org/x/crypto/pbkdf2"
)

func getSalt(n int) []byte {
	nonce := make([]byte, n)
	//if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	//	panic(err.Error())
	//}
        for i, _ :=range nonce {
		nonce[i]='a'
	}
	return (nonce)

}
func getKey(n int) []byte {
	nonce := make([]byte, n)
        for i, _ :=range nonce {
		nonce[i]='b'
	}
	return (nonce)

}
func main() {

	msg := "hello"
	passwd := "qwerty"
	mode := "cbc"
	size := 32

	argCount := len(os.Args[1:])
	if argCount > 0 {
		msg = os.Args[1]
	}
	if argCount > 1 {
		passwd = os.Args[2]
	}
	if argCount > 2 {
		mode = os.Args[3]
	}
	if argCount > 3 {
		size, _ = strconv.Atoi(os.Args[4])
	}

	pwsalt := getSalt(16) // 96 bits for nonce/IV

	key := pbkdf2.Key([]byte(passwd), pwsalt, 5, size, sha256.New)

	key = getKey(32)
	fmt.Printf("passwd %s, pwsalt %s,key: %v\n", passwd, pwsalt, key)
	block, _ := aes.NewCipher(key)
	fmt.Printf("block: %v\n", block)

	var salt []byte
	var plain []byte
	var ciphertext []byte

	plaintext := []byte(msg)

	if mode == "gcm" {
		// AEAD
		salt = getSalt(12)
		aesgcm, _ := cipher.NewGCM(block)
		ciphertext = aesgcm.Seal(nil, salt, plaintext, nil)
		plain, _ = aesgcm.Open(nil, salt, ciphertext, nil)
	} else if mode == "cbc" {
		// Block cipher
		plain = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)
		ciphertext = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)
		salt = getSalt(16)
		fmt.Printf("salt: %v\n", salt)
		pkcs7 := pad.NewPKCS7(aes.BlockSize)
		pad1 := pkcs7.Pad(plaintext)
		fmt.Printf("pad1: %v\n", pad1)
		blk := cipher.NewCBCEncrypter(block, salt)
		blk.CryptBlocks(ciphertext, pad1)
		blk = cipher.NewCBCDecrypter(block, salt)
		blk.CryptBlocks(plain, ciphertext)
		plain, _ = pkcs7.Unpad(plain)

	} else if mode == "cfb" {
		// Stream cipher
		salt = getSalt(aes.BlockSize)
		plain = make([]byte, len(plaintext))
		ciphertext = make([]byte, len(plaintext))

		stream := cipher.NewCFBEncrypter(block, salt)
		stream.XORKeyStream(ciphertext, plaintext)
		stream = cipher.NewCFBDecrypter(block, salt)
		stream.XORKeyStream(plain, ciphertext)
	}

	fmt.Printf("Mode:\t\t%s\n", strings.ToUpper(mode))
	fmt.Printf("Key size:\t%d bits\n", size*8)
	fmt.Printf("Message:\t%s\n", msg)

	fmt.Printf("Password:\t%s\n", passwd)
	fmt.Printf("Password Salt:\t%x\n", pwsalt)
	fmt.Printf("\nKey:\t\t%x\n", key)
	fmt.Printf("\nCipher:\t\t%x\n", ciphertext)

	fmt.Printf("Salt:\t\t%x\n", salt)
	fmt.Printf("\nDecrypted:\t%s\n", plain)
}

