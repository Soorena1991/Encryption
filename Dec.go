package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func help() {
	fmt.Println("dec input_file_address key_file_address output_file_address\tdcrypts the input file\ndec --help or dec -h\tshows this message")
}

func hash(data []byte) []byte {
	hashArray := sha3.Sum256(data)
	return hashArray[:]
}

func decrypt(data, pass []byte) []byte {
	aesBlock, _ := aes.NewCipher(hash(pass))
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	nonce, cipherText := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		panic(err.Error())
	}
	return plainText
}

func main() {
	BadCommand := errors.New("Bad command\nEnter \"dec --help\" or \"dec -h\" to see the instruction")
	if len(os.Args) != 4 {
		if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
			help()
			os.Exit(1)
		}
		panic(BadCommand)
	}
	//Open the file containing the string to be decrypted
	inputFile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err.Error())
	}
	//Read input from the input file
	inpuFileInfo, err := inputFile.Stat()
	inputData := make([]byte, inpuFileInfo.Size())
	_, err = inputFile.Read(inputData)
	if err != nil {
		panic(err.Error())
	}
	inputFile.Close()
	//Open the key file
	keyFile, err := os.Open(os.Args[2])
	if err != nil {
		panic(err.Error())
	}
	//Read key from key file
	inpuFileInfo, err = keyFile.Stat()
	key := make([]byte, inpuFileInfo.Size())
	_, err = keyFile.Read(key)
	if err != nil {
		panic(err.Error())
	}
	keyFile.Close()
	//Create output file
	outputFile, err := os.Create(os.Args[3])
	if err != nil {
		panic(err.Error())
	}
	_, err = outputFile.Write(decrypt(inputData, key))
	if err != nil {
		panic(err.Error())
	}
	outputFile.Close()
}
