

.PHONY: all
all: run

.PHONY: deps
deps:
	go get -u github.com/gorilla/mux
	go get -u github.com/dgrijalva/jwt-go

.PHONY: client
client:
	go build -o oauthclient.exe cmd/oauthclient/main.go

.PHONY: server
server:
	go build -o oauthserver.exe cmd/oauthserver/main.go

.PHONY: runs
runs: server
	./oauthserver.exe -port 8884

.PHONY: run
run: build
	./oauthclient.exe -port 8488