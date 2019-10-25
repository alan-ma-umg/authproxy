package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
)

type rsaKeyChain struct {
	Keys []rsaKeyInfo `json:"keys"`
}

type rsaKeyInfo struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	X5t    string   `json:"x5t"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	X5c    []string `json:"x5c"`
	Issuer string   `json:"issuer"`
	rsaKey rsa.PublicKey
}

var (
	keyInfoURL = flag.String("keyInfoURL", "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/discovery/v2.0/keys", "URL with JWT key info")
	target     = flag.String("target", "http://target", "Back end server to connect to")
	port       = flag.Int("port", 8884, "port to listen on")
	keyData    rsaKeyChain
)

func proxyHandler(p *httputil.ReverseProxy, url *url.URL) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearerHeader, "Bearer ") {
			w.Header().Set("X-Authenticate-Error", "No bearer token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		jwtToken := bearerHeader[len("Bearer "):]

		var verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

		/* 		token, parseErr := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		   			// Don't forget to validate the alg is what you expect:
		   			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		   				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		   			}

		   			for _, elem := range keyData.Keys {
		   				if elem.Kid == token.Header["kid"] {
		   					return &elem.rsaKey, nil
		   				}
		   			}

		   			return nil, fmt.Errorf("RSA key not found: %v", token.Header["x5t"])
		   		})

		   		if parseErr != nil {
		   			w.Header().Set("X-Authenticate-Error", parseErr.Error())
		   			w.WriteHeader(http.StatusUnauthorized)
		   			return
		   		}

		   		if !token.Valid {
		   			w.Header().Set("X-Authenticate-Error", "token invalid")
		   			w.WriteHeader(http.StatusUnauthorized)
		   			return
		   		}
		*/

		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host
		r.URL.Path = mux.Vars(r)["rest"]
		log.Printf("Proxy to %s\n", r.URL.String())

		p.ServeHTTP(w, r)
	}
}

func main() {
	flag.Parse()
	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("Listening on https://%s\n", addr)

	remote, err := url.Parse(*target)
	if err != nil {
		panic(err)
	}

	provider, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/microsoft.com/v2.0/.well-known/openid-configuration")

	keyInfoResp, keyInfoErr := http.Get(*keyInfoURL)
	if keyInfoErr != nil {
		log.Fatal("Cannot request key data:" + keyInfoErr.Error())
	}

	keyInfoBodyText, keyInfoBodyErr := ioutil.ReadAll(keyInfoResp.Body)
	if keyInfoBodyErr != nil {
		log.Fatal("Cannot read read key data:" + keyInfoBodyErr.Error())
	}

	err = json.Unmarshal(keyInfoBodyText, &keyData)
	if err != nil {
		log.Fatal("Cannot read unmarshal key data:" + err.Error() + string(keyInfoBodyText))
	}

	for keyIndex := range keyData.Keys {
		elem := &keyData.Keys[keyIndex]
		decodedExponent, _ := base64.URLEncoding.DecodeString(elem.E)
		elem.rsaKey.E = 0
		var multiplier = 1 << uint32(len(decodedExponent)*8-8)
		for i := 0; i < len(decodedExponent); i++ {
			elem.rsaKey.E += multiplier * int(decodedExponent[i])
			multiplier >>= 8
		}

		decodedN, _ := base64.URLEncoding.DecodeString(elem.N)
		elem.rsaKey.N = big.NewInt(0)
		elem.rsaKey.N.SetBytes(decodedN)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)

	r := mux.NewRouter()
	r.HandleFunc("/{rest:.*}", proxyHandler(proxy, remote))

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
