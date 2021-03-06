build: build_amd64

build_amd64:
	GOOS=linux GOARCH=amd64 go build -o wg-server-amd64 main.go