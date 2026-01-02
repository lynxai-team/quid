package tokens_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	turbo64 "github.com/cristalhq/base64"
	"github.com/golang-jwt/jwt/v5"

	"github.com/LynxAIeu/emo"
	"github.com/LynxAIeu/quid/tokens"
)

var cases = []struct {
	name       string
	timeout    string
	maxTTL     string
	user       string
	groups     []string
	orgs       []string
	want       string
	wantGenErr bool
	wantNewErr bool
}{{
	name:       "HS256=HMAC-SHA256",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "HS384=HMAC-SHA384",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "HS512=HMAC-SHA512",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "RS256=RSASSA-PKCSv15-SHA256",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "",
	groups:     nil,
	orgs:       nil,
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "RS384=RSASSA-PKCSv15-SHA384",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "",
	groups:     nil,
	orgs:       nil,
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "RS512=RSASSA-PKCSv15-SHA512",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "",
	groups:     nil,
	orgs:       nil,
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "ES256=ECDSA-P256-SHA256",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "ES384=ECDSA-P384-SHA384",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "ES512=ECDSA-P521-SHA512",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}, {
	name:       "EdDSA=Ed25519",
	timeout:    "11m",
	maxTTL:     "12m",
	user:       "me",
	groups:     []string{"dev"},
	orgs:       []string{"wikipedia"},
	want:       "",
	wantGenErr: false,
	wantNewErr: false,
}}

func TestNewAccessToken(t *testing.T) {
	t.Parallel()

	emo.GlobalColoring(false)

	for i, c := range cases {
		i := i
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			algo := strings.Split(c.name, "=")[0]

			privateKey, err := tokens.GenerateSigningKey(algo)
			if (err != nil) != c.wantGenErr {
				t.Errorf("GenerateSigningKey() error = %v, wantGenErr %v", err, c.wantGenErr)
				return
			}
			t.Log(algo+" Private key len=", len(privateKey))

			publicDER, err := tokens.PrivateDER2PublicDER(algo, privateKey)
			if err != nil {
				t.Error("Public(privateKey) error:", err)
				return
			}
			t.Log(algo+" Public  key len=", len(publicDER))

			publicKey, err := tokens.PrivateDER2Public(algo, privateKey)
			if err != nil {
				t.Error("PrivateToPublic("+algo+",privateKey) error:", err)
				return
			}

			publicKey2, err := tokens.ParsePublicDER(algo, publicDER)
			if err != nil {
				t.Error("ParsePublicDER("+algo+",der) error:", err)
				return
			}

			if !reflect.DeepEqual(publicKey2, publicKey) {
				t.Error("public keys are not equal")
			}

			tokenStr, err := tokens.GenAccessTokenWithAlgo(algo, c.timeout, c.maxTTL, c.user, c.groups, c.orgs, privateKey)
			if (err != nil) != c.wantNewErr {
				t.Errorf("NewAccessToken() error = %v, wantNewErr %v", err, c.wantNewErr)
				return
			}
			t.Log(algo+" AccessToken len=", len(tokenStr), tokenStr)

			validator := jwt.NewParser(jwt.WithValidMethods([]string{algo}))

			var claims tokens.AccessClaims
			f := func(*jwt.Token) (any, error) { return publicKey, nil }
			_, err = validator.ParseWithClaims(tokenStr, &claims, f)
			if err != nil {
				t.Error("ParseWithClaims error:", err)
				return
			}

			if err := tokens.ValidAccessToken(tokenStr, algo, publicDER); err != nil {
				t.Error("ValidAccessToken:", err)
				return
			}

			var publicDERStr string
			if i%2 == 0 {
				publicDERStr = hex.EncodeToString(publicDER)
			} else {
				publicDERStr = base64.RawURLEncoding.EncodeToString(publicDER)
			}

			algoKey := algo + ":" + publicDERStr
			v, err := tokens.NewVerifier(algoKey, true)
			if err != nil {
				if algo[:2] == "RS" { // TODO
					return
				}
				t.Error("tokens.NewVerifier err:", err)
				t.Error("tokens.NewVerifier algoKey:", algoKey)
				t.Error("tokens.NewVerifier key len:", len(publicDERStr))
				return
			}

			if v == nil {
				return
			}

			ac, err := v.Claims([]byte(tokenStr))
			if err != nil {
				t.Error("Verifier.Claims error:", err)
				return
			}

			if !reflect.DeepEqual(ac, &claims) {
				t.Error("Different Claims")
				t.Error("claims=", claims)
				t.Error("ac    =", ac)
			}
		})
	}
}

/* To verify the JWT signature, what is the most pertinent?
   1. sign header+payload, then base64.Encode our signature, and finally compare the two base64 signatures
   2. sign header+payload, then base64.Decode their signature, and finally compare the two binary signatures
   Are the strings much less performant than []byte?

   Let's bench it:

go test -bench=. -benchmem ./...
goos: linux
goarch: amd64
pkg: github.com/LynxAIeu/quid/tokens
cpu: AMD Ryzen 9 3900X 12-Core Processor
BenchmarkBase64Encode-24         5913382   209.2 ns/op   144 B/op   1 allocs/op
BenchmarkBase64EncodeTurbo-24    8053846   144.6 ns/op   144 B/op   1 allocs/op
BenchmarkBase64EncodeString-24   3928515   297.4 ns/op   256 B/op   2 allocs/op
BenchmarkBase64Decode-24         4375579   277.0 ns/op   112 B/op   1 allocs/op
BenchmarkBase64DecodeTurbo-24    5554828   206.1 ns/op   112 B/op   1 allocs/op
BenchmarkBase64DecodeString-24   3331362   376.8 ns/op   256 B/op   2 allocs/op
PASS
ok      github.com/LynxAIeu/quid/tokens     6.254s
*/

const jwtSample = `{"usr":"jane","grp":["group1","group2"],"org":["organization1","organization2"],"exp":1595950745}`

func BenchmarkBase64Encode(b *testing.B) {
	srcTxt := []byte(jwtSample)
	B64size := base64.RawURLEncoding.EncodedLen(len(srcTxt))
	b64BytesSame := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64BytesSame, []byte(srcTxt))
	b64BytesDiff := make([]byte, B64size)
	_, err := rand.Read(b64BytesDiff)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstBase64Bytes := make([]byte, B64size)
		base64.RawURLEncoding.Encode(dstBase64Bytes, srcTxt)
		_ = dstBase64Bytes

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstBase64Bytes, b64BytesSame)
		} else {
			ok = bytes.Equal(dstBase64Bytes, b64BytesDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}

func BenchmarkBase64EncodeTurbo(b *testing.B) {
	srcTxt := []byte(jwtSample)
	B64size := base64.RawURLEncoding.EncodedLen(len(srcTxt))
	b64BytesSame := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64BytesSame, []byte(srcTxt))
	b64BytesDiff := make([]byte, B64size)
	_, err := rand.Read(b64BytesDiff)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstBase64Bytes := make([]byte, B64size)
		turbo64.RawURLEncoding.Encode(dstBase64Bytes, srcTxt)
		_ = dstBase64Bytes

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstBase64Bytes, b64BytesSame)
		} else {
			ok = bytes.Equal(dstBase64Bytes, b64BytesDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}

func BenchmarkBase64EncodeString(b *testing.B) {
	srcTxt := []byte(jwtSample)
	B64size := base64.RawURLEncoding.EncodedLen(len(srcTxt))
	b64BytesSame := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64BytesSame, []byte(srcTxt))
	b64BytesDiff := make([]byte, B64size)
	_, err := rand.Read(b64BytesDiff)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstBase64Bytes := make([]byte, B64size)
		base64.RawURLEncoding.Encode(dstBase64Bytes, []byte(srcTxt))

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstBase64Bytes, b64BytesSame)
		} else {
			ok = bytes.Equal(dstBase64Bytes, b64BytesDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}

func BenchmarkBase64Decode(b *testing.B) {
	txtSame := []byte(jwtSample)
	txtDiff := make([]byte, len(txtSame))
	_, err := rand.Read(txtDiff)
	if err != nil {
		b.Fatal(err)
	}

	B64size := base64.RawURLEncoding.EncodedLen(len(txtSame))
	b64 := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64, txtSame)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstTxt := make([]byte, len(txtSame))
		n, err := base64.RawURLEncoding.Decode(dstTxt, b64)
		if err != nil {
			panic(err)
		}
		dstTxt = dstTxt[:n]

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstTxt, txtSame)
		} else {
			ok = bytes.Equal(dstTxt, txtDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}

func BenchmarkBase64DecodeTurbo(b *testing.B) {
	txtSame := []byte(jwtSample)
	txtDiff := make([]byte, len(txtSame))
	_, err := rand.Read(txtDiff)
	if err != nil {
		b.Fatal(err)
	}

	B64size := base64.RawURLEncoding.EncodedLen(len(txtSame))
	b64 := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64, txtSame)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstTxt := make([]byte, len(txtSame))
		_, err := turbo64.RawURLEncoding.Decode(dstTxt, b64)
		if err != nil {
			panic(err)
		}

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstTxt, txtSame)
		} else {
			ok = bytes.Equal(dstTxt, txtDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}

func BenchmarkBase64DecodeString(b *testing.B) {
	txtSame := []byte(jwtSample)
	txtDiff := make([]byte, len(txtSame))
	_, err := rand.Read(txtDiff)
	if err != nil {
		b.Fatal(err)
	}

	B64size := base64.RawURLEncoding.EncodedLen(len(txtSame))
	b64Bytes := make([]byte, B64size)
	base64.RawURLEncoding.Encode(b64Bytes, txtSame)
	b64String := string(b64Bytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstTxt, err := base64.RawURLEncoding.DecodeString(b64String)
		if err != nil {
			panic(err)
		}

		same := i%2 == 0
		var ok bool
		if same {
			ok = bytes.Equal(dstTxt, txtSame)
		} else {
			ok = bytes.Equal(dstTxt, txtDiff)
		}

		if ok != same {
			b.Errorf("#%d same=%v ok=%v", i, same, ok)
		}
	}
}
