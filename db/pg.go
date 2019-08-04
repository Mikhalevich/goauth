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

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Emails(id SERIAL PRIMARY KEY, userID integer REFERENCES Users(id) ON DELETE CASCADE ON UPDATE CASCADE, email varchar(100) UNIQUE, prim boolean, verified boolean, verification_code varchar(10));")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Sessions(id SERIAL PRIMARY KEY, userID integer REFERENCES Users(id) ON DELETE CASCADE ON UPDATE CASCADE, name varchar(100), value varchar(100) UNIQUE, expires integer);")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS UnknownRequest(id SERIAL PRIMARY KEY, ip varchar(50) UNIQUE, url varchar(256) NOT NULL);")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS LoginRequest(id SERIAL PRIMARY KEY, unknownID integer REFERENCES UnknownRequest(id) ON DELETE CASCADE ON UPDATE CASCADE, time integer NOT NULL)")
	if err != nil {
		return err
	}

	return nil
}

func (p *Postgres) Close() error {
	return p.db.Close()
}

func (p *Postgres) emailsByUserID(userID int) ([]goauth.Email, error) {
	rows, err := p.db.Query("SELECT email, prim, verified, verification_code FROM Emails WHERE userID = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	emails := []goauth.Email{}
	for rows.Next() {
		e := goauth.Email{}
		if err := rows.Scan(&e.Email, &e.Primary, &e.Verified, &e.VerificationCode); err != nil {
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

func (p *Postgres) userByQuery(query string, args ...interface{}) (*goauth.User, error) {
	row := p.db.QueryRow(query, args...)

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

func (p *Postgres) GetByName(name string) (*goauth.User, error) {
	return p.userByQuery("SELECT * FROM Users WHERE name = $1", name)
}

func (p *Postgres) GetByEmail(email string) (*goauth.User, error) {
	return p.userByQuery("SELECT * FROM Users WHERE Users.id = (SELECT userID FROM Emails WHERE email = $1)", email)
}

func (p *Postgres) GetBySession(sessionValue string) (*goauth.User, error) {
	return p.userByQuery("SELECT Users.* FROM Users INNER JOIN Sessions ON Users.id = Sessions.userID WHERE Sessions.value = $1", sessionValue)
}

func (p *Postgres) addEmailTx(userID int, e goauth.Email, tx Transaction) error {
	_, err := tx.Exec("INSERT INTO Emails(userID, email, prim, verified, verification_code) VALUES($1, $2, $3, $4, $5)", userID, e.Email, e.Primary, e.Verified, e.VerificationCode)
	return err
}

func (p *Postgres) AddEmail(userID int, e goauth.Email) error {
	return p.addEmailTx(userID, e, p.db)
}

func (p *Postgres) addSessionTx(userID int, s goauth.Session, tx Transaction) error {
	_, err := tx.Exec("INSERT INTO Sessions(userID, name, value, expires) VALUES($1, $2, $3, $4)", userID, s.Name, s.Value, s.Expires)
	return err
}

func (p *Postgres) AddSession(userID int, s goauth.Session) error {
	return p.addSessionTx(userID, s, p.db)
}

func (p *Postgres) Add(u *goauth.User) error {
	return WithTransaction(p.db, func(tx Transaction) error {
		var id int
		err := tx.QueryRow("INSERT INTO Users(name, password) VALUES($1, $2) RETURNING id", u.Name, u.Pwd).Scan(&id)
		if err != nil {
			return err
		}

		u.ID = id

		for _, s := range u.Sessions {
			err = p.addSessionTx(id, s, tx)
			if err != nil {
				return err
			}
		}

		for _, e := range u.Emails {
			err := p.addEmailTx(id, e, tx)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (p *Postgres) Get(ip string, limitRequests int) (*goauth.UnknownRequest, error) {
	row := p.db.QueryRow("SELECT id, ip, url FROM UnknownRequest WHERE ip = $1", ip)

	ur := goauth.UnknownRequest{}
	err := row.Scan(&ur.ID, &ur.IP, &ur.URL)

	if err == sql.ErrNoRows {
		return nil, goauth.ErrNotExists
	} else if err != nil {
		return nil, err
	}

	rows, err := p.db.Query("SELECT time FROM LoginRequest WHERE unknownID = $1 ORDER BY time desc LIMIT $2", ur.ID, limitRequests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	requests := []goauth.LoginRequest{}
	for rows.Next() {
		r := goauth.LoginRequest{}
		if err := rows.Scan(&r.Time); err != nil {
			return nil, err
		}
		requests = append(requests, r)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	ur.Requests = requests

	return &ur, nil
}

func (p *Postgres) AddRequest(ur *goauth.UnknownRequest) error {
	return WithTransaction(p.db, func(tx Transaction) error {
		err := tx.QueryRow("INSERT INTO UnknownRequest(ip, url) VALUES($1, $2) RETURNING id", ur.IP, ur.URL).Scan(&ur.ID)
		if err != nil {
			return err
		}

		for _, r := range ur.Requests {
			err = p.addLoginTx(ur.ID, r.Time, tx)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (p *Postgres) addLoginTx(ID int, time int64, tx Transaction) error {
	_, err := tx.Exec("INSERT INTO LoginRequest(unknownID, time) VALUES($1, $2)", ID, time)
	return err
}

func (p *Postgres) AddLogin(ID int, time int64) error {
	return p.addLoginTx(ID, time, p.db)
}
