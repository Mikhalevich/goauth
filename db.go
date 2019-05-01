package goauth

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"time"
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

type Session struct {
	ID      int
	Value   string
	Expires int64
}

func NewSession(expirePeriod int64) *Session {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return &Session{
		ID:      0,
		Value:   base64.URLEncoding.EncodeToString(bytes),
		Expires: time.Now().Unix() + expirePeriod,
	}
}

func (s *Session) IsExpired() bool {
	return s.Expires < time.Now().Unix()
}

type Email struct {
	ID       int
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
	return Session{}, errors.New("Not found")
}

type LoginRequest struct {
	ID   int
	Time int64
}

type UnknownRequest struct {
	ID       int
	IP       string
	URL      string
	Requests []LoginRequest
}

type Requester interface {
	Request(ip string) (*UnknownRequest, error)
	AddRequest(UnknownRequest)
}

type Userer interface {
	UserByName(name string) (User, error)
}
