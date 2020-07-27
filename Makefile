default: build

GO=CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go
LDFLAGS=
NAME=hamburg

mod:
	$(GO) mod tidy

build: mod
	$(GO) build ${LDFLAGS} -o $(NAME) main.go
