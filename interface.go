package goauth

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

var (
	ErrNotExists = errors.New("not exist")
)

type Password [sha1.Size]byte

func (p Password) IsEmpty() bool {
	for _, value := range p {
		if value != 0 {
			return false
		}
	}
	return true
}

func NewPassword(p string) Password {
	if p != "" {
		return sha1.Sum([]byte(p))
	}
	return Password{}
}

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
	Email    string
	Verified bool
	Primary  bool
}

type User struct {
	ID       int
	Name     string
	Pwd      Password
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

type LoginRequest struct {
	Time int64
}

type UnknownRequest struct {
	ID       int
	IP       string
	URL      string
	Requests []LoginRequest
}

func NewUnknownRequest(ip, url string) *UnknownRequest {
	return &UnknownRequest{
		IP:       ip,
		URL:      url,
		Requests: make([]LoginRequest, 0),
	}
}

type Requester interface {
	Get(ip string) (*UnknownRequest, error)
	Add(UnknownRequest) error
	AddLogin(ID int, time int64) error
}

type Userer interface {
	GetByName(name string) (User, error)
	GetBySession(value string) (User, error)
	Add(u *User) error
	AddSession(userID int, s Session) error
}

type Sessioner interface {
	Create() Session
	Find(r *http.Request) (Session, error)
}
