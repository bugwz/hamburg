default: linux

GOOS_LINUX=GOOS=linux 
GOOS_DARWIN=GOOS=darwin
GO=CGO_ENABLED=1 GOARCH=amd64 go
LDFLAGS=
NAME=hamburg

mod:
	$(GO) mod tidy

linux: mod
	$(GOOS_LINUX) $(GO) build ${LDFLAGS} -o $(NAME) main.go

darwin: mod
	$(GOOS_DARWIN) $(GO) build ${LDFLAGS} -o $(NAME) main.go
