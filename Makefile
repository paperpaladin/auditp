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

# Every deliberate defect in t/mutants.txt, built in a scratch directory
# and run against the whole suite.  Not part of make test: it builds the
# program 47 times and takes about a minute.
mutants: all
	@t/mutate.sh

# The whole corpus at stride 1, which is about 200,000 cases and some
# minutes.  make test runs the first 4 KB at stride 13.
truncate: all
	@python3 t/truncate.py --stride 1 --bytes 0 --lines 1 --flips 2000

vet: $(SRC)
	$(GO) vet ./...

clean:
	rm -f auditp auditp-cover
	rm -rf scratch

.PHONY: all test mutants truncate vet clean
