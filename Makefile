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
# program once per entry and takes about an hour at 118 of them.  The
# count in a comment here went stale the moment the table grew, so
# t/run.sh asks t/patch.py --check instead, which counts the table it
# reads and says whether every pattern still applies.
mutants: all
	@t/mutate.sh

# The whole corpus at stride 1, which is about 200,000 cases and some
# minutes.  make test runs the first 4 KB at stride 13.
truncate: all
	@python3 t/truncate.py --stride 1 --bytes 0 --lines 1 --flips 2000

# Twenty-five fuzz seeds instead of the three make test runs.
fuzz: all
	@for s in $$(seq 1 25); do \
		python3 t/fuzz.py --seed $$s --count 800 --out t/tmp.fz.log >/dev/null; \
		./auditp -o flat -i t/tmp.fz.log > t/tmp.fz.ours; \
		python3 t/oracle.py --interpret t/tmp.fz.log > t/tmp.fz.orc 2>/dev/null; \
		printf 'seed %s: ' $$s; \
		python3 t/compare.py --oracle-declines --known t/known-diff.txt \
			 --known-may-be-unmet --ours t/tmp.fz.ours --oracle t/tmp.fz.orc | head -1; \
	done; rm -f t/tmp.fz.*

vet: $(SRC)
	$(GO) vet ./...

clean:
	rm -f auditp auditp-cover
	rm -rf scratch

.PHONY: all test mutants truncate fuzz vet clean
