package sastoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

const (
	SAS_TOKEN_TEMP = "SharedAccessSignature sig=%s&se=%s&skn=%s&sr=%s"
)

// Implement URLEncode based on Values struct in net/url
func URLEncode(plain string) string {
	values := url.Values{}
	values.Add("enc", plain)
	return values.Encode()[4:]
}

// HMAC-SHA256 encode
func HmacSHA256(str2sig, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(str2sig))
	hmacsha256 := mac.Sum(nil)
	return hmacsha256
}


// Per Azure Configuration to generate SAS Token 
func GenerateSASToken(expiry, keyName, uri, key string) string {
	sr := URLEncode(uri)
	str2sig := sr + "\n" + expiry
	hmacsha256 := HmacSHA256(str2sig, key)
	sig := URLEncode(base64.StdEncoding.EncodeToString(hmacsha256))
	sasToken := fmt.Sprintf(SAS_TOKEN_TEMP, sig, expiry, keyName, sr)
	return sasToken
}