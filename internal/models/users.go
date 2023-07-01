package models

import (
	"database/sql"
	"errors"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"time"
)

// User Used for Authentication
type User struct {
	ID             int
	Name           string
	Email          string
	HashedPassword []byte
	Created        time.Time
}
type UserModel struct {
	DB *sql.DB
}
type UserModelInterface interface {
	Insert(name, email, passowrd string) error
	Authenticate(email, password string) (int, error)
	Exists(id int) (bool, error)
	Get(id int) (*User, error)
	PasswordUpdate(id int, currentPassword, newPassword string) error
}

func (m *UserModel) Insert(name, email, password string) error {
	// Create a bcrypt hash of the plain-text password.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	stmt := `insert into users (name,email,hashed_password,created)values (?,?,?,UTC_TIMESTAMP())`
	_, err = m.DB.Exec(stmt, name, email, string(hashedPassword))
	if err != nil {
		var mySQLError *mysql.MySQLError
		if errors.As(err, &mySQLError) {
			if mySQLError.Number == 1062 && strings.Contains(mySQLError.Message, "users_uc_email") {
				return ErrDuplicateEmail
			}
		}
		return err
	}
	return nil

}
func (m *UserModel) Authenticate(email, password string) (int, error) {
	// Retrieve the id and hashed password associated with the given email. If // no matching email exists we return the ErrInvalidCredentials error.
	var id int
	var hashedPassword []byte
	stmt := "SELECT id, hashed_password FROM users WHERE email = ?"
	err := m.DB.QueryRow(stmt, email).Scan(&id, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvalidCredentials
		} else {
			return 0, err
		}
	}
	// Check whether the hashed password and plain-text password provided match. // If they don't, we return the ErrInvalidCredentials error.
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return 0, ErrInvalidCredentials
		} else {
			return 0, err
		}
	}
	// Otherwise, the password is correct. Return the user ID.
	return id, nil
}
func (m *UserModel) Exists(id int) (bool, error) {
	var exists bool
	stmt := "select exists(select true from users where id = ?)"
	err := m.DB.QueryRow(stmt, id).Scan(&exists)

	return exists, err
}
func (m *UserModel) Get(id int) (*User, error) {
	var user User
	stmt := `select id,name,email,created from users where id= ?`
	err := m.DB.QueryRow(stmt, id).Scan(&user.ID, &user.Name, &user.Email, &user.Created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoRecord
		} else {
			return nil, err
		}
	}
	return &user, nil
}
func (m *UserModel) PasswordUpdate(id int, currentPassword, newPassword string) error {
	var currentHashedPassword []byte

	stmt := "select hashed_password from users where id=?"
	err := m.DB.QueryRow(stmt, id).Scan(&currentHashedPassword)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword(currentHashedPassword, []byte(currentPassword))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		} else {
			return err
		}
	}
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	stmt = "update users set hashed_password=? where id=?"
	_, err = m.DB.Exec(stmt, string(newHashedPassword), id)
	return err
}
