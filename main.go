package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	random "math/rand"
	"time"
)

const (
	AES128 = 16
	AES192 = 24
	AES256 = 32
)


//Esta funcion tiene una semilla con la
//Fecha asi devuelve numeros aleatorios diferentes
func generateKeyAes256() []byte{
	random.Seed(time.Now().Unix())
	result := make([]byte,AES256)
	for i:= 0;i < AES256 ;i++  {
		result[i] = byte(33 +random.Intn(123-33))
	}
	return result
}

//Esta funcion se encarga cifrar el mensaje,
//pasandole como parametro la clave y el mensaje
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}
//Esta funcion se encarga descifrar el mensaje,
//pasandole como parametro la clave y el mensaje
func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func main() {
	message := "Este es el mensaje a encriptar"
	key := generateKeyAes256()[:AES128]
	fmt.Printf("Clave Unica : %s\n", key)
	fmt.Printf("Mensaje Original: %s\n", message)

	ciphertext, err := encrypt(key, []byte(message))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mensaje Cifrado: %0x\n", ciphertext)
	result, err := decrypt(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mensaje Decifrado: %s\n", result)
}