LDFLAGS ?= -w -s -X main.BuildDate=$(shell date +%F)
PREFIX ?= /usr

all: build
build: janus ssh-decrypt
install: $(PREFIX)/bin/janus $(PREFIX)/bin/ssh-decrypt

.PHONY: janus
janus:
	@go build  -ldflags '$(LDFLAGS)' -o $@ *.go

.PHONY: ssh-decrypt
ssh-decrypt:
	@go build -ldflags '$(LDFLAGS)' -o $@ cmd/decrypt.go

$(PREFIX)/bin/janus: janus
	install -p -D -m 0755 $< $@

$(PREFIX)/bin/ssh-decrypt: ssh-decrypt
	install -p -D -m 0755 $< $@

.PHONY: clean
clean:
	rm -f janus ssh-decrypt coverage.out agent.sock

.PHONY: coverage.out
coverage.out:
	@go test -v -cover -coverprofile $(@) ./...

.PHONY: cover
cover: coverage.out
	@go tool cover -func $<

.PHONY: vet
vet:
	@go vet ./...

.PHONY: fmt
fmt:
	@test -z "$$(gofmt -d ./ | tee /dev/stderr)"

.PHONY: test
test: cover vet fmt 

.PHONY: run	
run: janus
	@SSH_AUTH_SOCK="$(shell pwd)/agent.sock" ./janus