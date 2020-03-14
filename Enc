package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/sha3"
)

func help() {
	fmt.Println("enc input_file_address key_length key_output_file_address")
}

func hash(data []byte) []byte {
	hashArray := sha3.Sum256(data)
	return hashArray[:]
}

func encrypt(data []byte, passphrase []byte) []byte {
	block, _ := aes.NewCipher(hash(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func main() {
	if len(os.Args) != 4 {
		if len(os.Args) == 1 {
			help()
		} else {
			fmt.Println("commandoo ride")
		}
		os.Exit(1)
	}
	//Open the file containing the string
	inputFile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err.Error())
	}
	keylen, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err.Error())
	}
	//Read from the input file
	inpuFileInfo, err := inputFile.Stat()
	buff := make([]byte, inpuFileInfo.Size())
	_, err = inputFile.Read(buff)
	if err != nil {
		panic(err.Error())
	}
	inputFile.Close()
	//Generate a random key
	key := make([]byte, keylen)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	//Create output file
	outputFile, err := os.Create(os.Args[2] + ".enc")
	if err != nil {
		panic(err.Error())
	}
	_, err = outputFile.Write(encrypt(buff, key))
	if err != nil {
		panic(err.Error())
	}
	outputFile.Close()
	//Create key file
	keyFile, err := os.Create(os.Args[2] + ".key")
	if err != nil {
		panic(err.Error())
	}
	_, err = keyFile.Write(key)
	if err != nil {
		panic(err.Error())
	}
	keyFile.Close()
}
