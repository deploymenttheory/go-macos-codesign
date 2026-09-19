.PHONY: build snapshot check test verify lint research research-cms research-signature research-certificates release-check

build:
	goreleaser build --snapshot --clean --parallelism 2

snapshot:
	goreleaser release --snapshot --clean --parallelism 2

check:
	goreleaser check

test:
	CGO_ENABLED=0 go test ./...

verify:
	python3 scripts/guards.py
	python3 scripts/verify.py

lint:
	golangci-lint run

research:
	python3 scripts/extract-sdk.py

research-cms:
	python3 scripts/extract-cms.py

research-signature:
	python3 scripts/extract-signature.py

research-certificates:
	python3 scripts/extract-certificates.py

release-check:
	python3 scripts/guards.py --require-complete
