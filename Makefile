.PHONY: build dev-deps dev-env fmt run test

build:
	go build -o file-share ./cmd/file-share

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

run:
	go run ./cmd/file-share serve

# Postgres-backed tests use FILE_SHARE_TEST_DATABASE_URL, or start a
# throwaway cluster with local initdb/pg_ctl. FILE_SHARE_REQUIRE_POSTGRES=1
# turns "skip" into "fail".
test:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	FILE_SHARE_REQUIRE_POSTGRES=1 go test -race ./...

# Local PostgreSQL and Garage for `make run` and the Paseo serve script.
dev-deps:
	docker compose -f compose.dev.yaml up -d --wait
	./dev/garage-init

# Write .env from .env.example (which matches compose.dev.yaml) with a fresh
# MCP_SECRET. Refuses to overwrite an existing .env.
dev-env:
	test ! -e .env
	umask 077 && sed -e "s|^MCP_SECRET=.*|MCP_SECRET=$$(openssl rand -hex 24)|" .env.example > .env
