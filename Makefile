LDFLAGS ?= -w -s -X main.BuildDate=$(shell date +%F)
PREFIX ?= /usr

all: build
build: janus
install: $(PREFIX)/bin/janus

.PHONY: janus
janus:
	@go build  -ldflags '$(LDFLAGS)' -o $@ *.go

$(PREFIX)/bin/janus: janus
	install -p -D -m 0750 $< $@

.PHONY: clean
clean:
	rm -f janus coverage.out agent.sock

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