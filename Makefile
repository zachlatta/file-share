.PHONY: build fmt run test

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
