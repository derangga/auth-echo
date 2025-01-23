package connection

import (
	"auth-echo/server/config"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

const postgreDriver = "postgres"

// NewPostgresDatabase is used to create new Postgres setup
func NewPostgresDatabase(config config.DatabaseConfig) *sqlx.DB {
	param := "sslmode=disable"

	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?%s",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Name,
		param,
	)

	fmt.Println(connStr)

	db, err := sqlx.Open(postgreDriver, connStr)
	if err != nil {
		log.Fatal("failed to open db connection:", err.Error())
	}

	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.MaxLifetime)

	if err = db.Ping(); err != nil {
		log.Fatal("failed to ping db connection:", err.Error())
	}

	return db
}