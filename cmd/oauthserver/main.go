package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
)

var (
	providerURL = flag.String("provider", "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0", "provider")
	target      = flag.String("target", "http://ifconfig.co", "Back end server to connect to")
	port        = flag.Int("port", 8884, "port to listen on")
	clientID    = flag.String("clientId", "bc5bd1c6-ee3d-4200-af33-c27d8c1289b5", "APP client id")
	certFile    = flag.String("certFile", "cert.pem", "Cert file for TLS (default: cert.pem)")
	keyFile     = flag.String("keyFile", "key.pem", "Private key file for TLS (default: key.pem)")
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
)

var claims struct {
	Email string `json:"upn"`
	Name  string `json:"name"`
}

func proxyHandler(p *httputil.ReverseProxy, url *url.URL) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearerHeader, "Bearer ") {
			w.Header().Set("X-Authenticate-Error", "No bearer token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		jwtToken := bearerHeader[len("Bearer "):]

		token, err := verifier.Verify(r.Context(), jwtToken)
		if err != nil {
			w.Header().Set("X-Authenticate-Error", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err := token.Claims(&claims); err != nil {
			w.Header().Set("X-Authenticate-Error", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

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
	provider, err = oidc.NewProvider(context.Background(), *providerURL)
	if err != nil {
		log.Fatalf("Error creating oidc provider: %v", err)
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: *clientID})

	proxy := httputil.NewSingleHostReverseProxy(remote)

	r := mux.NewRouter()
	r.HandleFunc("/{rest:.*}", proxyHandler(proxy, remote))

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
