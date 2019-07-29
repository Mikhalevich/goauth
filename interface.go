package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

var (
	ErrNotExists = errors.New("not exist")
)

type Session struct {
	Name    string
	Value   string
	Expires int64
}

func NewSession(name string, expire int64) *Session {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return &Session{
		Name:    name,
		Value:   base64.URLEncoding.EncodeToString(bytes),
		Expires: time.Now().Unix() + expire,
	}
}

func (s *Session) IsExpired() bool {
	return s.Expires < time.Now().Unix()
}

type Email struct {
	Email            string
	Verified         bool
	Primary          bool
	VerificationCode string
}

type User struct {
	ID       int
	Name     string
	Pwd      string
	Emails   []Email
	Sessions []Session
}

func (u *User) Session(value string) (Session, error) {
	for _, session := range u.Sessions {
		if session.Value == value {
			return session, nil
		}
	}
	return Session{}, ErrNotExists
}

func (u *User) Email(address string) (Email, error) {
	for _, e := range u.Emails {
		if e.Email == address {
			return e, nil
		}
	}

	return Email{}, ErrNotExists
}

type LoginRequest struct {
	Time int64
}

type UnknownRequest struct {
	ID       int
	IP       string
	URL      string
	Requests []LoginRequest
}

func (ur *UnknownRequest) RequestsAfter(ut int64) int {
	count := 0
	for _, r := range ur.Requests {
		if r.Time > ut {
			count++
		}
	}
	return count
}

func NewUnknownRequest(ip, url string) *UnknownRequest {
	return &UnknownRequest{
		IP:       ip,
		URL:      url,
		Requests: make([]LoginRequest, 0),
	}
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
