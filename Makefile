include .env

migrate_up:
	migrate -path database/migrations/ -database "postgresql://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_DB_HOST):$(POSTGRES_DB_PORT)/$(POSTGRES_DB)?sslmode=disable" -verbose up

migrate_down:
	migrate -path database/migrations/ -database "postgresql://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_DB_HOST):$(POSTGRES_DB_PORT)/$(POSTGRES_DB)?sslmode=disable" -verbose down 1

run_api:
	go run app/api/main.go

mocks_gen:
	mockgen -source=usecase/usecase.go -destination=mocks/usecase/usecase.go
	mockgen -source=repository/repository.go -destination=mocks/repository/repository.go

run_test:
	go test ./... -coverprofile=cover.out

coverage_html:
	go tool cover -html=cover.out 