package cookie

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

func createSecureCookie(cookieKey string) (*securecookie.SecureCookie, error) {
	if cookieKey == "" {
		rKey := securecookie.GenerateRandomKey(96)
		if rKey == nil {
			return nil, errors.New("failed to generate random key")
		}
		cookieKey = base64.StdEncoding.EncodeToString(rKey)

		fmt.Printf("Using random CookieKey: %s\n", cookieKey)
	}

	k, err := base64.StdEncoding.DecodeString(cookieKey)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString()")
	}
	if len(k) < 96 {
		return nil, errors.New("CookieKey to short.  Expect minimum of 96 bytes. (128 bytes when base64 encoded)")
	}

	hSaltIndex := int(k[55] % 4)
	hIndex := int(k[7]%4 + 12)
	saltIndex := int(k[73]%4 + 48)
	index := int(k[37]%4 + 60)

	hash, err := pbkdf2.Key(sha256.New, string(k[hIndex:hIndex+32]), k[hSaltIndex:hSaltIndex+8], 4356+hIndex*saltIndex, 64)
	if err != nil {
		return nil, errors.Wrap(err, "pbkdf2.Key()")
	}

	block, err := pbkdf2.Key(sha256.New, string(k[index:index+32]), k[saltIndex:saltIndex+8], 4491+(hSaltIndex+1)*index, 32)
	if err != nil {
		return nil, errors.Wrap(err, "pbkdf2.Key()")
	}

	return securecookie.New(hash, block), nil
}
