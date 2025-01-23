include .env

migrate_up:
	migrate -path database/migrations/ -database "postgresql://$(DB_USERNAME):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" -verbose up

migrate_down:
	migrate -path db/migrations -database "postgresql://$(DB_USERNAME):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" -verbose down

run_api:
	go run app/api/main.go

mocks_gen:
	mockgen -source=usecase/usecase.go -destination=mocks/usecase/usecase.go
	mockgen -source=repository/repository.go -destination=mocks/repository/repository.go

run_test:
	go test ./... -coverprofile=cover.out

coverage_html:
	go tool cover -html=cover.out 