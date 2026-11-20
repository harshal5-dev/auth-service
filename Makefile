include .env
export

MIGRATIONS_DIR := ./migrations

.PHONY: migrate-up migrate-down migrate-status sqlc run test

## Run Goose migrations up
migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" up

## Roll back the last Goose migration
migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" down

## Check Goose migration status
migrate-status:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" status

sqlc:
	sqlc generate

run:
	go run ./cmd/api/main.go

test:
	go test -v -race ./...
