package main

import (
	"encoding/base64"
	"encoding/json"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/recrypt"
	"math/big"
	"net/http"
)

type EncryptRequest struct {
	AESKey string `json:"aesKey"`
	PubKey string `json:"pubKey"`
}

type RecryptRequest struct {
	OwnerPriKey string `json:"ownerPriKey"`
	OwnerPubKey string `json:"ownerPubKey"`
	RecipientPubKey string `json:"recipientPubKey"`
	Capsule string `json:"capsule"`
}

type DecryptAtMyFilesRequest struct {
	PriKey string `json:"priKey"`
	PubKey string `json:"pubKey"`
	AESKeyCipher string `json:"aesKeyCipher"`
	Capsule string `json:"capsule"`
}

type DecryptAtSharedFilesRequest struct {
	PriKey string `json:"priKey"`
	PubKey string `json:"pubKey"`
	AESKeyCipher string `json:"aesKeyCipher"`
	RecryptPubX string `json:"recryptPubX"`
	RecryptCapsule string `json:"recryptCapsule"`
}

func main() {
	http.HandleFunc("/generateKeys", handleGenerateKeys)
	http.HandleFunc("/encrypt", handleEncrypt)
	http.HandleFunc("/recrypt", handleRecrypt)
	http.HandleFunc("/decryptAtMyFiles", handleDecryptAtMyFiles)
	http.HandleFunc("/decryptAtSharedFiles", handleDecryptAtSharedFiles)
	http.ListenAndServe(":10000", nil)
}

func handleGenerateKeys(w http.ResponseWriter, r *http.Request) {
	priKey, pubKey, _ := curve.GenerateKeys()
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	priKeyBytes := priKey.D.Bytes()

	response := map[string]interface{}{
		"publicKey": pubKeyBytes,
		"privateKey": priKeyBytes,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)

	fmt.Println("Deserialized Public Key:", pubKey)
	fmt.Println("Public Key (byte[]):", pubKeyBytes)
	fmt.Println("Deserialized Private Key:", priKey)
	fmt.Println("Private Key (byte[]):", priKeyBytes)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var requestData EncryptRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Println("Public Key (base64):", requestData.PubKey)

	decodedPubKey, err := base64.StdEncoding.DecodeString(requestData.PubKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}

	fmt.Println("Public Key (byte[]):", decodedPubKey)

	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, decodedPubKey)
	if x == nil || y == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	fmt.Println("Deserialized Public Key:", pubKey)

	plainAESKey := requestData.AESKey
	fmt.Println("plaintext:", plainAESKey)

	cipherText, capsule, err := recrypt.Encrypt(plainAESKey, pubKey)
	if err != nil {
		fmt.Println(err)
	}
	capsuleAsBytes, err := recrypt.EncodeCapsule(*capsule)
	if err != nil {
		fmt.Println("encode error:", err)
	}

	fmt.Println("capsule before encode:", capsule)
	fmt.Println("capsule after encode:", capsuleAsBytes)
	fmt.Println("ciphertext:", cipherText)

	response := map[string]interface{}{
		"cipher": cipherText,
		"capsule": capsuleAsBytes,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func handleRecrypt(w http.ResponseWriter, r *http.Request) {
	var requestData RecryptRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Println("Owner Private Key (base64):", requestData.OwnerPriKey)
	fmt.Println("Owner Public Key (base64):", requestData.OwnerPubKey)
	fmt.Println("Recipient Public Key (base64):", requestData.RecipientPubKey)
	fmt.Println("Capsule (base64):", requestData.Capsule)

	decodedOwnerPriKey, err := base64.StdEncoding.DecodeString(requestData.OwnerPriKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedOwnerPubKey, err := base64.StdEncoding.DecodeString(requestData.OwnerPubKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedRecipientPubKey, err := base64.StdEncoding.DecodeString(requestData.RecipientPubKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedCapsule, err := base64.StdEncoding.DecodeString(requestData.Capsule)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}

	fmt.Println("Owner Private Key (byte[]):", decodedOwnerPriKey)
	fmt.Println("Owner Public Key (byte[]):", decodedOwnerPubKey)
	fmt.Println("Recipient Public Key (byte[]):", decodedRecipientPubKey)
	fmt.Println("Capsule (byte[]):", decodedCapsule)

	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, decodedOwnerPubKey)
	if x == nil || y == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	ownerPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	fmt.Println("Deserialized Owner Public Key:", ownerPubKey)

	ownerPriKey := &ecdsa.PrivateKey{
		PublicKey: *ownerPubKey,
		D:         new(big.Int).SetBytes(decodedOwnerPriKey),
	}

	fmt.Println("Deserialized Owner Private Key:", ownerPriKey)

	curve2 := elliptic.P256()
	x2, y2 := elliptic.Unmarshal(curve2, decodedRecipientPubKey)
	if x2 == nil || y2 == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	recipientPubKey := &ecdsa.PublicKey{
		Curve: curve2,
		X:     x2,
		Y:     y2,
	}

	fmt.Println("Deserialized Recipient Public Key:", recipientPubKey)

	capsule, err := recrypt.DecodeCapsule(decodedCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	fmt.Println("Deserialized Capsule:", capsule)

	rk, pubX, err := recrypt.ReKeyGen(ownerPriKey, recipientPubKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("rk:", rk)
	fmt.Println("pubX:", pubX)
	
	newCapsule, err := recrypt.ReEncryption(rk, &capsule)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("newCapsule:", newCapsule)

	pubXBytes := elliptic.Marshal(pubX.Curve, pubX.X, pubX.Y)
	newCapsuleAsBytes, err := recrypt.EncodeCapsule(*newCapsule)
	if err != nil {
		fmt.Println("encode error:", err)
	}

	fmt.Println("pubX in bytes:", pubXBytes)
	fmt.Println("new capsule after encode:", newCapsuleAsBytes)

	response := map[string]interface{}{
		"pubX": pubXBytes,
		"newCapsule": newCapsuleAsBytes,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func handleDecryptAtMyFiles(w http.ResponseWriter, r *http.Request) {
	var requestData DecryptAtMyFilesRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Println("Private Key (base64):", requestData.PriKey)
	fmt.Println("Public Key (base64):", requestData.PubKey)
	fmt.Println("Ciphertext (base64):", requestData.AESKeyCipher)
	fmt.Println("Capsule (base64):", requestData.Capsule)

	decodedPriKey, err := base64.StdEncoding.DecodeString(requestData.PriKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedPubKey, err := base64.StdEncoding.DecodeString(requestData.PubKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedAESKeyCipher, err := base64.StdEncoding.DecodeString(requestData.AESKeyCipher)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedCapsule, err := base64.StdEncoding.DecodeString(requestData.Capsule)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}

	fmt.Println("Private Key (byte[]):", decodedPriKey)
	fmt.Println("Public Key (byte[]):", decodedPubKey)
	fmt.Println("Ciphertext (byte[]):", decodedAESKeyCipher)
	fmt.Println("Capsule (byte[]):", decodedCapsule)

	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, decodedPubKey)
	if x == nil || y == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	fmt.Println("Deserialized Public Key:", pubKey)

	priKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(decodedPriKey),
	}

	fmt.Println("Deserialized Private Key:", priKey)

	capsule, err := recrypt.DecodeCapsule(decodedCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	fmt.Println("Deserialized Capsule:", capsule)

	plainAESKey, err := recrypt.DecryptOnMyPriKey(priKey, &capsule, decodedAESKeyCipher)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("PlainText:", string(plainAESKey))

	response := map[string]interface{}{
		"plaintext": string(plainAESKey),
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func handleDecryptAtSharedFiles(w http.ResponseWriter, r *http.Request) {
	var requestData DecryptAtSharedFilesRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	fmt.Println("Private Key (base64):", requestData.PriKey)
	fmt.Println("Public Key (base64):", requestData.PubKey)
	fmt.Println("Ciphertext (base64):", requestData.AESKeyCipher)
	fmt.Println("Recrypt PubX (base64):", requestData.RecryptPubX)
	fmt.Println("Recrypt Capsule (base64):", requestData.RecryptCapsule)

	decodedPriKey, err := base64.StdEncoding.DecodeString(requestData.PriKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedPubKey, err := base64.StdEncoding.DecodeString(requestData.PubKey)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedAESKeyCipher, err := base64.StdEncoding.DecodeString(requestData.AESKeyCipher)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedRecryptPubX, err := base64.StdEncoding.DecodeString(requestData.RecryptPubX)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	decodedRecryptCapsule, err := base64.StdEncoding.DecodeString(requestData.RecryptCapsule)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}

	fmt.Println("Private Key (byte[]):", decodedPriKey)
	fmt.Println("Public Key (byte[]):", decodedPubKey)
	fmt.Println("Ciphertext (byte[]):", decodedAESKeyCipher)
	fmt.Println("Recrypt PubX (byte[]):", decodedRecryptPubX)
	fmt.Println("Recrypt Capsule (byte[]):", decodedRecryptCapsule)

	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, decodedPubKey)
	if x == nil || y == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	fmt.Println("Deserialized Public Key:", pubKey)

	priKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(decodedPriKey),
	}

	fmt.Println("Deserialized Private Key:", priKey)

	curve2 := elliptic.P256()
	x2, y2 := elliptic.Unmarshal(curve2, decodedRecryptPubX)
	if x2 == nil || y2 == nil {
		fmt.Println("Failed to unmarshal the public key.")
		return
	}
	pubX := &ecdsa.PublicKey{
		Curve: curve2,
		X:     x2,
		Y:     y2,
	}

	fmt.Println("Deserialized Recrypt PubX:", pubX)

	recryptCapsule, err := recrypt.DecodeCapsule(decodedRecryptCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	fmt.Println("Deserialized Recrypt Capsule:", recryptCapsule)

	plainAESKey, err := recrypt.Decrypt(priKey, &recryptCapsule, pubX, decodedAESKeyCipher)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("PlainText:", string(plainAESKey))

	response := map[string]interface{}{
		"plaintext": string(plainAESKey),
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}