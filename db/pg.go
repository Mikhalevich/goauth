package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/Mikhalevich/goauth"
	_ "github.com/lib/pq"
)

type PGParams struct {
	User     string
	Password string
	DBName   string
	Host     string
	Port     int
	SSLMode  string
}

type Postgres struct {
	db *sql.DB
}

func NewPostgres(p PGParams) (*Postgres, error) {
	if p.DBName == "" {
		return nil, errors.New("empty database name")
	}

	if p.User == "" {
		p.User = "postgres"
	}

	if p.Host == "" {
		p.Host = "localhost"
	}

	if p.Port == 0 {
		p.Port = 5432
	}

	if p.SSLMode == "" {
		p.SSLMode = "disable"
	}

	pgDB, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d sslmode=%s", p.User, p.Password, p.DBName, p.Host, p.Port, p.SSLMode))
	if err != nil {
		return nil, err
	}

	err = createSchema(pgDB)
	if err != nil {
		return nil, err
	}

	return &Postgres{
		db: pgDB,
	}, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS Users(id SERIAL PRIMARY KEY, name varchar(50) UNIQUE, password varchar(100));")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Emails(id SERIAL PRIMARY KEY, userID integer REFERENCES Users(id) ON DELETE CASCADE ON UPDATE CASCADE, email varchar(100) UNIQUE, prim boolean, verified boolean);")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Sessions(id SERIAL PRIMARY KEY, userID integer REFERENCES Users(id), name varchar(100), value varchar(100) UNIQUE, expires integer);")
	if err != nil {
		return err
	}

	return nil
}

func (p *Postgres) Close() error {
	return p.db.Close()
}

func (p *Postgres) emailsByUserID(userID int) ([]goauth.Email, error) {
	rows, err := p.db.Query("SELECT email, verified, prim FROM Emails WHERE userID = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	emails := []goauth.Email{}
	for rows.Next() {
		e := goauth.Email{}
		if err := rows.Scan(&e.Email, &e.Verified, &e.Primary); err != nil {
			return nil, err
		}
		emails = append(emails, e)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return emails, nil
}

func (p *Postgres) sessionsByUserID(userID int) ([]goauth.Session, error) {
	rows, err := p.db.Query("SELECT name, value, expires FROM Sessions WHERE userID = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := []goauth.Session{}
	for rows.Next() {
		s := goauth.Session{}
		if err := rows.Scan(&s.Name, &s.Value, &s.Expires); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (p *Postgres) GetByName(name string) (*goauth.User, error) {
	row := p.db.QueryRow("SELECT * FROM Users WHERE name = $1", name)

	user := goauth.User{}
	err := row.Scan(&user.ID, &user.Name, &user.Pwd)

	if err == sql.ErrNoRows {
		return nil, goauth.ErrNotExists
	} else if err != nil {
		return nil, err
	}

	emails, err := p.emailsByUserID(user.ID)
	if err != nil {
		return nil, err
	}
	user.Emails = emails

	sessions, err := p.sessionsByUserID(user.ID)
	if err != nil {
		return nil, err
	}
	user.Sessions = sessions

	return &user, nil
}

func (p *Postgres) GetBySession(value string) (*goauth.User, error) {
	return nil, nil
}

func (p *Postgres) Add(u *goauth.User) error {
	return nil
}

func (p *Postgres) AddSession(userID int, s goauth.Session) error {
	return nil
}
