package goauth

import (
	"net/http"
)

type Authentifier interface {
	GetUser(r *http.Request) (*User, error)
	AuthorizeByName(name, password, ip string) (*Session, error)
	RegisterByName(name, password string) (*Session, error)
	SendEmailVerificationCode(callbackURL string, userID int, email Email)
	ValidateEmail(email string, code string) error
}

type Requester interface {
	Get(ip string, limitRequests int) (*UnknownRequest, error)
	AddRequest(r *UnknownRequest) error
	AddLogin(ID int, time int64) error
}

type Userer interface {
	GetByName(name string) (*User, error)
	GetByEmail(email string) (*User, error)
	GetBySession(value string) (*User, error)
	Add(u *User) error
	AddEmail(userID int, email Email) error
	AddSession(userID int, s Session) error
}

type Sessioner interface {
	Create() Session
	Find(r *http.Request) (Session, error)
}

type Emailer interface {
	Sent(emailTo string, contentType string, body string) error
}
