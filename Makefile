.PHONY: all test vet lint

all: test vet lint

test:
	go test

vet:
	go vet ./...

lint:
	golint .
