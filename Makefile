# Standard library only: there is no module to download and no network step.
GO      ?= go
GOFLAGS ?= -mod=mod
SRC     := $(wildcard *.go)

all: auditp

auditp: $(SRC) go.mod
	$(GO) build $(GOFLAGS) -o $@ .

# The oracle is /usr/sbin/ausearch. t/run.sh refuses to run without it.
test: all
	@t/run.sh

vet: $(SRC)
	$(GO) vet ./...

clean:
	rm -f auditp auditp-cover
	rm -rf scratch

.PHONY: all test vet clean
