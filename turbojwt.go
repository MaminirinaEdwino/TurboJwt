package turbojwt

import (
	"encoding/base64"
	"encoding/json"
)

func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Encode(secret string, playload map[string]interface{}) (string, error) {
	header := map[string]string {
		"alg": "HS256",
		"typ":"JWT",
	}

	headerJson, _ := json.Marshal(header)
	encodedHeader := base64Encode(headerJson)
}
