.PHONY: build snapshot check test verify lint research research-cms research-signature research-certificates research-timestamps research-bundles research-dmg research-removal research-writer research-inventory research-paths release-check

build:
	goreleaser build --snapshot --clean --parallelism 2

snapshot:
	goreleaser release --snapshot --clean --parallelism 2 --skip=sign

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

research-timestamps:
	go run scripts/extract-timestamps.go
	go run scripts/extract-timestamp-http.go

research-bundles:
	go run scripts/extract-bundles.go
	go run scripts/extract-bundle-plists.go
	go run scripts/extract-nested.go
	go run scripts/extract-nested-apps.go
	go run scripts/extract-bundle-layouts.go
	go run scripts/extract-bundle-discovery.go

research-dmg:
	go run scripts/extract-dmg.go

research-removal:
	go run scripts/extract-removal.go

research-writer:
	go run scripts/extract-writer.go

research-inventory:
	go run scripts/probe-cli.go

research-paths:
	go run scripts/extract-paths.go

release-check:
	python3 scripts/guards.py --require-complete
