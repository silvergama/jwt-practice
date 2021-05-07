package user

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	QueryFindByEmail = `
	SELECT name, email, password, role
	FROM users
	WHERE email = ?
	`
	QueryStore = `
		INSERT INTO user(nome, email, password, role)
		VALUES(?, ?, ?, ?)
	`
)

type UseCase interface {
	FindByEmail(email string) (*User, error)
	Store(user *User) error
}

type Service struct {
	DB *sql.DB
}

func (s *Service) FindByEmail(email string) (*User, error) {
	user := &User{}

	stmt, err := s.DB.Prepare(QueryFindByEmail)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	err = stmt.QueryRow(email).Scan(&user.Name, &user.Email, &user.Password, &user.Role)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) Store(user *User) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(QueryStore)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(user.Name, user.Email, user.Password, user.Role)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}
