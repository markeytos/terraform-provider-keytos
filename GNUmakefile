default: fmt vet mod-tidy lint install generate

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

mod-tidy:
	go mod tidy

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: fmt vet mod-tidy lint test testacc build install generate
