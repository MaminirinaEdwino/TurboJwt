package turbojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)
// base64Encode allow to generate base64.URLEncoding
func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
// generateHmac generate a hashed data for the jwt signature
func generateHmac(secret string, unsignedToken string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(unsignedToken))
	return base64Encode(h.Sum(nil))
}
// Encode generate jwt token by using the secret and payload variable
func Encode(secret string, playload map[string]interface{}) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJson, _ := json.Marshal(header)
	encodedHeader := base64Encode(headerJson)
	payloadJson, _ := json.Marshal(playload)
	encodedPayload := base64Encode(payloadJson)
	unsignedToken := encodedHeader + "." + encodedPayload
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(unsignedToken))
	signature := base64Encode(h.Sum(nil))
	return unsignedToken + "." + signature, nil
}



func Verify(secret string, token string) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("Invalide Token")
	}

	unsignedPart := parts[0]+"."+parts[1]
	signature := generateHmac(secret, unsignedPart)

	if hmac.Equal([]byte(signature), []byte(parts[2])) {
		return true, nil
	}
	return false, fmt.Errorf("Invalide signature.")
}
