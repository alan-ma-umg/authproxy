

.PHONY: all
all: run

.PHONY: deps
deps:
	go get -u github.com/gorilla/mux
	go get -u github.com/coreos/go-oidc

.PHONY: client
client:
	go build -o oauthclient.exe cmd/oauthclient/main.go

.PHONY: server
server:
	go build -o oauthserver.exe cmd/oauthserver/main.go

cert.pem key.pem:
	openssl req -newkey rsa:4096 -subj "/CN=localhost" -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem

.PHONY: runs
runs: server cert.pem key.pem
	./oauthserver.exe -port 8884

.PHONY: run
run: client
	./oauthclient.exe -port 8488

