package goauth

import (
	"errors"
	"net/http"
	"time"
)

const (
	SessionExpirePeriod = 1 * 60 * 60 * 24 * 30 // sec
)

var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNoSuchUser    = errors.New("no such user")
	ErrManyRequests  = errors.New("many requests")
	ErrPwdNotMatch   = errors.New("passwords not match")
)

type Authentificator struct {
	db  Userer
	req Requester
	ses Sessioner
}

func NewAuthentificator(userDB Userer, r Requester, s Sessioner) *Authentificator {
	return &Authentificator{
		db:  userDB,
		req: r,
		ses: s,
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

	user, err := a.db.UserByName(name)
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
	a.db.AddSession(user.ID, session)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authentificator) RegisterByPassword(name, password string) error {
	_, err := a.db.UserByName(name)
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
	return a.db.AddUser(u)
}
