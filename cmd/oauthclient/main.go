package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gorilla/mux"
)

type authTokenJSON struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

var (
	target       = flag.String("target", "http://target", "XAP proxy server to connect to")
	clientID     = flag.String("clientId", "bc5bd1c6-ee3d-4200-af33-c27d8c1289b5", "APP client id")
	port         = flag.Int("port", 8488, "port to listen on")
	currentToken authTokenJSON
)

func login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://login.microsoftonline.com/microsoft.com/oauth2/v2.0/authorize?"+
		"client_id="+*clientID+
		"&response_type=code"+
		"&redirect_uri=http%3A%2F%2Flocalhost:"+fmt.Sprintf("%d", *port)+"%2Fauth"+
		//"&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"+
		"&response_mode=query"+
		// "&prompt=consent"+
		"&scope=openid%20offline_access"+
		"&state=12345", http.StatusTemporaryRedirect)

}

func auth(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	newCode := r.Form["code"]
	if len(newCode) != 1 {
		w.Write([]byte(fmt.Sprintf("<html>Missing code</html>")))
		return
	}

	resp, err := http.PostForm("https://login.microsoftonline.com/microsoft.com/oauth2/v2.0/token", url.Values{
		"client_id": {*clientID},
		"scope":     {"openid"},
		"code":      {newCode[0]},
		//"redirect_uri": {"https://login.microsoftonline.com/common/oauth2/nativeclient"},
		"redirect_uri": {"http://localhost:" + fmt.Sprintf("%d", *port) + "/auth"},
		"grant_type":   {"authorization_code"}})

	if err != nil {
		w.Write([]byte(fmt.Sprintf("<html>Could not read post to oauth2/token: %s</html>", err.Error())))
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("<html>Could not read body: %s</html>", err.Error())))
		return
	}

	log.Println("Body: " + string(body))
	parseErr := json.Unmarshal(body, &currentToken)
	if parseErr != nil {
		log.Println("Could not parse access token: " + parseErr.Error())
	}

	http.Redirect(w, r, "/status", http.StatusTemporaryRedirect)
}

func status(w http.ResponseWriter, r *http.Request) {
	bytes, _ := json.Marshal(currentToken)
	w.Write([]byte(fmt.Sprintf("<html>Token: %s</html>", string(bytes))))
}

func proxyHandler(p *httputil.ReverseProxy, url *url.URL) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host
		r.Header.Set("Authentication", "Bearer "+currentToken.AccessToken)
		r.URL.Path = mux.Vars(r)["rest"]
		log.Printf("Proxy to %s\n", r.URL.String())

		p.ServeHTTP(w, r)
	}
}

// TODO: background thread to refresh token

func main() {
	flag.Parse()
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("Go to http://%s/login\n", addr)

	remote, err := url.Parse(*target)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)

	r := mux.NewRouter()
	r.HandleFunc("/login", login).Methods("GET")
	r.HandleFunc("/auth", auth).Methods("GET")
	r.HandleFunc("/status", status).Methods("GET")
	r.HandleFunc("/{rest:.*}", proxyHandler(proxy, remote))

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
