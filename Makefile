.PHONY: build install clean

build:
	go build -o kilovault ./cmd/kilovault

install:
	go install ./cmd/kilovault

clean:
	rm -f kilovault

test:
	go test ./...
