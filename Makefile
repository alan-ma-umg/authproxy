

.PHONY: all
all: run

.PHONY: deps
deps:
	go get -u github.com/gorilla/mux
	go get -u github.com/dgrijalva/jwt-go

.PHONY: build
build:
	go build -o oauthclient.exe cmd/oauthclient/main.go

.PHONY: run
run: build
	./oauthclient.exe -port 8488