package goauth

import (
	"errors"
	"net/http"
	"time"
)

var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNoSuchUser    = errors.New("no such user")
	ErrManyRequests  = errors.New("many requests")
	ErrPwdNotMatch   = errors.New("passwords not match")
)

type Authentificator struct {
	user Userer
	req  Requester
	ses  Sessioner
}

func NewAuthentificator(u Userer, r Requester, s Sessioner) *Authentificator {
	return &Authentificator{
		user: u,
		req:  r,
		ses:  s,
	}
}

func (a *Authentificator) IsAuthorized(r *http.Request) bool {
	s, err := a.ses.Find(r)
	if err != nil {
		return false
	}

	if s.IsExpired() {
		return false
	}

	return true
}

func (a *Authentificator) Authorize(name, password, ip string) error {
	r, err := a.req.Request(ip)
	if err == ErrNotExists {
		r = NewUnknownRequest(ip, "")
		err = a.req.AddRequest(*r)
	}

	if err != nil {
		return err
	}

	if len(r.Requests) > 3 {
		return ErrManyRequests
	}

	user, err := a.user.UserByName(name)
	if err == ErrNotExists {
		return ErrNoSuchUser
	}

	if err != nil {
		return err
	}

	if user.Pwd != NewPassword(password) {
		a.req.AddLoginRequest(r.ID, time.Now().Unix())
		return ErrPwdNotMatch
	}

	session := a.ses.Create()
	a.user.AddSession(user.ID, session)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authentificator) RegisterByName(name, password string) error {
	_, err := a.user.UserByName(name)
	if err == nil {
		return ErrAlreadyExists
	}

	if err != ErrNotExists {
		return err
	}

	u := &User{
		Name:     name,
		Pwd:      NewPassword(password),
		Sessions: []Session{a.ses.Create()},
	}
	return a.user.AddUser(u)
}
