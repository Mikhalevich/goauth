package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/http"
	"time"
)

var (
	ErrNotAuthorized            = errors.New("not authorized")
	ErrAlreadyExists            = errors.New("already exists")
	ErrNoSuchUser               = errors.New("no such user")
	ErrManyRequests             = errors.New("many requests")
	ErrPwdNotMatch              = errors.New("passwords not match")
	ErrVerificationCodeNotMatch = errors.New("verification code not match")
)

type Authentificator struct {
	user  Userer
	req   Requester
	ses   Sessioner
	email Emailer
}

func NewAuthentificator(u Userer, r Requester, s Sessioner, e Emailer) *Authentificator {
	return &Authentificator{
		user:  u,
		req:   r,
		ses:   s,
		email: e,
	}
}

func (a *Authentificator) GetUser(r *http.Request) (*User, error) {
	reqSession, err := a.ses.Find(r)
	if err != nil {
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

func (a *Authentificator) AuthorizeByName(name, password, ip string) (*Session, error) {
	r, err := a.req.Get(ip, 3)
	if err == ErrNotExists {
		r = NewUnknownRequest(ip, "")
		err = a.req.AddRequest(r)
	}

	if err != nil {
		return nil, err
	}

	if r.RequestsAfter(time.Now().Add(-60*time.Second).Unix()) >= 3 {
		return nil, ErrManyRequests
	}

	user, err := a.user.GetByName(name)
	if err == ErrNotExists {
		return nil, ErrNoSuchUser
	}

	if err != nil {
		return nil, err
	}

	if user.Pwd != password {
		a.req.AddLogin(r.ID, time.Now().Unix())
		return nil, ErrPwdNotMatch
	}

	session := a.ses.Create()
	return &session, a.user.AddSession(user.ID, session)
}

func (a *Authentificator) RegisterByName(name, password string) (*Session, error) {
	_, err := a.user.GetByName(name)
	if err == nil {
		return nil, ErrAlreadyExists
	}

	if err != ErrNotExists {
		return nil, err
	}

	session := a.ses.Create()

	u := &User{
		Name:     name,
		Pwd:      password,
		Sessions: []Session{session},
	}
	return &session, a.user.Add(u)
}

func generateRandomID(size int) string {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (a *Authentificator) SendEmailVerificationCode(callbackURL string, userID int, email Email) error {
	email.VerificationCode = generateRandomID(10)
	err := a.user.AddEmail(userID, email)
	if err != nil {
		return err
	}

	link := fmt.Sprintf("%s?email=%s&code=%s", callbackURL, html.EscapeString(email.Email), html.EscapeString(email.VerificationCode))
	return a.email.Sent(email.Email, "text/plain", link)
}

func (a *Authentificator) ValidateEmail(email string, code string) error {
	u, err := a.user.GetByEmail(email)
	if err != nil {
		return err
	}

	e, err := u.Email(email)
	if err != nil {
		return err
	}

	if e.VerificationCode != html.UnescapeString(code) {
		return ErrVerificationCodeNotMatch
	}

	e.Verified = true
	e.VerificationCode = ""

	return a.user.AddEmail(u.ID, e)
}
