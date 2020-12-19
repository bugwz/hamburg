default: linux

GO=CGO_ENABLED=1 GOARCH=amd64 go
LDFLAGS=-ldflags=-compressdwarf=false
NAME=hamburg

mod:
	$(GO) mod tidy

linux: mod
	GOOS=linux $(GO) build ${LDFLAGS} -o $(NAME) main.go

darwin: mod
	GOOS=darwin $(GO) build ${LDFLAGS} -o $(NAME) main.go
