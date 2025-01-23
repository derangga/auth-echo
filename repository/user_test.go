package repository_test

import (
	"auth-echo/model/entity"
	"auth-echo/repository"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

// ref testing: https://github.com/jmoiron/sqlx/issues/204
func TestUserGetByID(t *testing.T) {
	mockDb, sqlxDB, mockSql := generateMockDb()
	defer mockDb.Close()

	repository := repository.NewUserRepository(sqlxDB)

	ctx := context.Background()

	tests := []struct{
		testname string
		sqldata entity.User
		initMock func(entity.User)
		assertion func(input entity.User, result entity.User, err error)
	} {
		{
			testname: "get by id and return correct user",
			sqldata: entity.User{
				ID: 1,
				Username: "testuname",
				Email: "mm@gmail.com",
				Name: "testname",
				Password: "password1",
			},
			initMock: func(u entity.User) {
				rows := sqlmock.NewRows([]string{"id", "username", "name", "email", "password"}).
					AddRow(u.ID, u.Username, u.Name, u.Email, u.Password)
				mockSql.ExpectQuery(`SELECT (.+) FROM users WHERE (.+)`).WithArgs(u.ID).WillReturnRows(rows)
			},
			assertion: func(input, result entity.User, err error) {
				assert.Equal(t, input, result)
				assert.NoError(t, err)
			},
		},
		{
			testname: "get by id and return error",
			sqldata: entity.User{
				ID: 1,
			},
			initMock: func(u entity.User) {
				mockSql.ExpectQuery(`SELECT (.+) FROM users WHERE (.+)`).WithArgs(u.ID).WillReturnError(errors.New("tidak ada"))
			},
			assertion: func(input, result entity.User, err error) {
				assert.Error(t, err)
				assert.Equal(t, "tidak ada", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testname, func(t *testing.T) {
			tt.initMock(tt.sqldata)
			result, err := repository.GetByID(ctx, tt.sqldata.ID)
			tt.assertion(tt.sqldata, result, err)
		})
	}
}

func TestUserGetByUsername(t *testing.T) {
	mockDb, sqlxDB, mockSql := generateMockDb()
	defer mockDb.Close()

	repository := repository.NewUserRepository(sqlxDB)

	ctx := context.Background()

	tests := []struct{
		testname string
		sqldata entity.User
		initMock func(entity.User)
		assertion func(input entity.User, result entity.User, err error)
	} {
		{
			testname: "get by username and return correct user",
			sqldata: entity.User{
				ID: 1,
				Username: "testuname",
				Email: "mm@gmail.com",
				Name: "testname",
				Password: "password1",
			},
			initMock: func(u entity.User) {
				rows := sqlmock.NewRows([]string{"id", "username", "name", "email", "password"}).
					AddRow(u.ID, u.Username, u.Name, u.Email, u.Password)
				mockSql.ExpectQuery(`SELECT (.+) FROM users WHERE (.+)`).WithArgs(u.Username).WillReturnRows(rows)
			},
			assertion: func(input, result entity.User, err error) {
				assert.Equal(t, input, result)
				assert.NoError(t, err)
			},
		},
		{
			testname: "get by username and return error",
			sqldata: entity.User{
				ID: 1,
			},
			initMock: func(u entity.User) {
				mockSql.ExpectQuery(`SELECT (.+) FROM users WHERE (.+)`).WithArgs(u.Username).WillReturnError(errors.New("tidak ada"))
			},
			assertion: func(input, result entity.User, err error) {
				assert.Error(t, err)
				assert.Equal(t, "tidak ada", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testname, func(t *testing.T) {
			tt.initMock(tt.sqldata)
			result, err := repository.GetByUsername(ctx, tt.sqldata.Username)
			tt.assertion(tt.sqldata, result, err)
		})
	}
}

func TestCreateUser(t *testing.T) {
	mockDb, sqlxDB, mockSql := generateMockDb()
	defer mockDb.Close()

	repository := repository.NewUserRepository(sqlxDB)

	ctx := context.Background()

	timedur := time.Now()
	mockUser := entity.User{
		Username: "usernametest",
		Name: "nametest",
		Role: "user",
		Email: "est@gmail.com",
		Password: "weweqas",
		CreatedAt: timedur,
	}
	insertUser := `INSERT INTO users\(username, name, email, role, password, created_at\) VALUES \(\?, \?, \?, \?, \?, \?\)`
	tests := []struct{
		nametest string
		mockdata entity.User
		initMock func(entity.User)
		assertion func(error)
	} {
		{
			nametest: "insert user return no error",
			mockdata: mockUser,
			initMock: func(u entity.User) {
				mockSql.ExpectPrepare(insertUser).ExpectQuery().
				WithArgs(
					u.Username,
					u.Name,
					u.Email,
					u.Role,
					u.Password,
					u.CreatedAt,
				). // Adjust to match user fields
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
			},
			assertion: func(err error) {
				assert.NoError(t, err)
			},
		},
		{
			nametest: "insert user return error",
			mockdata: mockUser,
			initMock: func(u entity.User) {
				mockSql.ExpectPrepare(insertUser).ExpectQuery().
				WithArgs(
					u.Username,
					u.Name,
					u.Email,
					u.Role,
					u.Password,
					u.CreatedAt,
				). // Adjust to match user fields
				WillReturnError(errors.New("failed insert"))
			},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.nametest, func(t *testing.T) {
			tt.initMock(tt.mockdata)
			err := repository.Create(ctx, &tt.mockdata)
			tt.assertion(err)
		})
	}
}

func generateMockDb() (*sql.DB, *sqlx.DB, sqlmock.Sqlmock,) {
	mockDb, mockSql, _ := sqlmock.New()
	sqlxDB := sqlx.NewDb(mockDb, "sqlmock")
	return mockDb, sqlxDB, mockSql
}