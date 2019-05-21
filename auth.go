package goauth

import (
	"errors"
	"net/http"
	"time"
)

var (
	ErrNotAuthorized = errors.New("not authorized")
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

func (a *Authentificator) GetUser(r *http.Request) (*User, error) {
	reqSession, err := a.ses.Find(r)
	if err != nil {
		return nil, ErrNotAuthorized
	}

	if reqSession.IsExpired() {
		return nil, ErrNotAuthorized
	}

	user, err := a.user.GetBySession(reqSession.Value)
	if err != nil {
		return nil, ErrNotAuthorized
	}

	storedSession, err := user.Session(reqSession.Value)
	if err != nil {
		return nil, ErrNotAuthorized
	}

	if storedSession.IsExpired() {
		return nil, ErrNotAuthorized
	}

	return user, nil
}

func (a *Authentificator) AuthorizeByName(name, password, ip string) error {
	r, err := a.req.Get(ip)
	if err == ErrNotExists {
		r = NewUnknownRequest(ip, "")
		err = a.req.Add(*r)
	}

	if err != nil {
		return err
	}

	if len(r.Requests) > 3 {
		return ErrManyRequests
	}

	user, err := a.user.GetByName(name)
	if err == ErrNotExists {
		return ErrNoSuchUser
	}

	if err != nil {
		return err
	}

	if user.Pwd != password {
		a.req.AddLogin(r.ID, time.Now().Unix())
		return ErrPwdNotMatch
	}

	session := a.ses.Create()
	err = a.user.AddSession(user.ID, session)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authentificator) RegisterByName(name, password string) error {
	_, err := a.user.GetByName(name)
	if err == nil {
		return ErrAlreadyExists
	}

	if err != ErrNotExists {
		return err
	}

	u := &User{
		Name:     name,
		Pwd:      password,
		Sessions: []Session{a.ses.Create()},
	}
	return a.user.Add(u)
}
