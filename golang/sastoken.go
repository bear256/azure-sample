package sastoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"time"
)

const (
	SAS_TOKEN_TEMP = "SharedAccessSignature sig=%s&se=%s&skn=%s&sr=%s"
)

func URLEncode(plain string) string {
	values := url.Values{}
	values.Add("enc", plain)
	return values.Encode()[4:]
}

func HmacSHA256(plain, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(str2sig))
	hmacsha256 := mac.Sum(nil)
	return hmacsha256
}

func GenerateSASToken(expiry, keyName, uri, key string) string {
	sr := URLEncode(uri)
	str2sig := sr + "\n" + expiry
	hmacsha256 := HmacSHA256(str2sig, key)
	sig := urlencode(base64.StdEncoding.EncodeToString([]byte(hmacsha256)))
	sasToken := fmt.Sprintf(SAS_TOKEN_TEMP, sig, expiry, keyName, sr)
	return sasToken
}