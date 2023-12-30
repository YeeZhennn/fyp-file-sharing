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

func deserializePubKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("Failed to unmarshal the public key.")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

func decodeToBytes(s string, w http.ResponseWriter) ([]byte, bool) {
	decodedData, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return nil, false
	}

	return decodedData, true
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

	fmt.Println("\n-----Key Generation-----")
	fmt.Println("Public Key:", pubKey)
	fmt.Println("Private Key:", priKey)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var requestData EncryptRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decodedPubKey, ok := decodeToBytes(requestData.PubKey, w)
	if !ok {
		return
	}

	pubKey, err := deserializePubKey(decodedPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	plainAESKey := requestData.AESKey
	
	cipherText, capsule, err := recrypt.Encrypt(plainAESKey, pubKey)
	if err != nil {
		fmt.Println(err)
	}
	capsuleAsBytes, err := recrypt.EncodeCapsule(*capsule)
	if err != nil {
		fmt.Println("encode error:", err)
	}

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

	fmt.Println("\n-----Encryption-----")
	fmt.Println("Public Key:", pubKey)
	fmt.Println("Plaintext:", plainAESKey)
	fmt.Println("Capsule:", capsule)
	fmt.Println("Ciphertext:", cipherText)
}

func handleRecrypt(w http.ResponseWriter, r *http.Request) {
	var requestData RecryptRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decodedOwnerPriKey, ok := decodeToBytes(requestData.OwnerPriKey, w)
	if !ok {
		return
	}
	decodedOwnerPubKey, ok := decodeToBytes(requestData.OwnerPubKey, w)
	if !ok {
		return
	}
	decodedRecipientPubKey, ok := decodeToBytes(requestData.RecipientPubKey, w)
	if !ok {
		return
	}
	decodedCapsule, ok := decodeToBytes(requestData.Capsule, w)
	if !ok {
		return
	}

	ownerPubKey, err := deserializePubKey(decodedOwnerPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	ownerPriKey := &ecdsa.PrivateKey{
		PublicKey: *ownerPubKey,
		D:         new(big.Int).SetBytes(decodedOwnerPriKey),
	}
	recipientPubKey, err := deserializePubKey(decodedRecipientPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	capsule, err := recrypt.DecodeCapsule(decodedCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	rk, pubX, err := recrypt.ReKeyGen(ownerPriKey, recipientPubKey)
	if err != nil {
		fmt.Println(err)
	}
	recryptCapsule, err := recrypt.ReEncryption(rk, &capsule)
	if err != nil {
		fmt.Println(err.Error())
	}
	
	pubXBytes := elliptic.Marshal(pubX.Curve, pubX.X, pubX.Y)
	recryptCapsuleAsBytes, err := recrypt.EncodeCapsule(*recryptCapsule)
	if err != nil {
		fmt.Println("encode error:", err)
	}

	response := map[string]interface{}{
		"pubX": pubXBytes,
		"recryptCapsule": recryptCapsuleAsBytes,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)

	fmt.Println("\n-----Re-Encryption-----")
	fmt.Println("Owner Public Key:", ownerPubKey)
	fmt.Println("Owner Private Key:", ownerPriKey)
	fmt.Println("Recipient Public Key:", recipientPubKey)
	fmt.Println("Capsule:", capsule)
	fmt.Println("Re-Encryption Key:", rk)
	fmt.Println("Recrypt pubX:", pubX)
	fmt.Println("Recrypt Capsule:", recryptCapsule)
}

func handleDecryptAtMyFiles(w http.ResponseWriter, r *http.Request) {
	var requestData DecryptAtMyFilesRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decodedPriKey, ok := decodeToBytes(requestData.PriKey, w)
	if !ok {
		return
	}
	decodedPubKey, ok := decodeToBytes(requestData.PubKey, w)
	if !ok {
		return
	}
	decodedAESKeyCipher, ok := decodeToBytes(requestData.AESKeyCipher, w)
	if !ok {
		return
	}
	decodedCapsule, ok := decodeToBytes(requestData.Capsule, w)
	if !ok {
		return
	}

	pubKey, err := deserializePubKey(decodedPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	priKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(decodedPriKey),
	}
	capsule, err := recrypt.DecodeCapsule(decodedCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	plainAESKey, err := recrypt.DecryptOnMyPriKey(priKey, &capsule, decodedAESKeyCipher)
	if err != nil {
		fmt.Println(err)
	}
	
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

	fmt.Println("\n-----Decryption (My Files)-----")
	fmt.Println("Public Key:", pubKey)
	fmt.Println("Private Key:", priKey)
	fmt.Println("Capsule:", capsule)
	fmt.Println("Ciphertext:", decodedAESKeyCipher)
	fmt.Println("Plaintext:", string(plainAESKey))
}

func handleDecryptAtSharedFiles(w http.ResponseWriter, r *http.Request) {
	var requestData DecryptAtSharedFilesRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decodedPriKey, ok := decodeToBytes(requestData.PriKey, w)
	if !ok {
		return
	}
	decodedPubKey, ok := decodeToBytes(requestData.PubKey, w)
	if !ok {
		return
	}
	decodedAESKeyCipher, ok := decodeToBytes(requestData.AESKeyCipher, w)
	if !ok {
		return
	}
	decodedRecryptPubX, ok := decodeToBytes(requestData.RecryptPubX, w)
	if !ok {
		return
	}
	decodedRecryptCapsule, ok := decodeToBytes(requestData.RecryptCapsule, w)
	if !ok {
		return
	}

	pubKey, err := deserializePubKey(decodedPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	priKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(decodedPriKey),
	}
	pubX, err := deserializePubKey(decodedRecryptPubX)
	if err != nil {
		fmt.Println(err)
		return
	}
	recryptCapsule, err := recrypt.DecodeCapsule(decodedRecryptCapsule)
	if err != nil {
		fmt.Println("decode error:", err)
	}

	plainAESKey, err := recrypt.Decrypt(priKey, &recryptCapsule, pubX, decodedAESKeyCipher)
	if err != nil {
		fmt.Println(err)
	}

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

	fmt.Println("\n-----Decryption (Shared Files)-----")
	fmt.Println("Public Key:", pubKey)
	fmt.Println("Private Key:", priKey)
	fmt.Println("Recrypt PubX:", pubX)
	fmt.Println("Recrypt Capsule:", recryptCapsule)
	fmt.Println("Ciphertext:", decodedAESKeyCipher)
	fmt.Println("Plaintext:", string(plainAESKey))
}