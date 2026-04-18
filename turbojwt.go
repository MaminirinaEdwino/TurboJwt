package turbojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

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
