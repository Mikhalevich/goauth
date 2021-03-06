package goauth

import "net/http"

type NullAuthentificator struct {
}

func NewNullAuthentificator() *NullAuthentificator {
	return &NullAuthentificator{}
}

func (n *NullAuthentificator) GetUser(r *http.Request) (*User, error) {
	return nil, nil
}

func (n *NullAuthentificator) AuthorizeByName(name, password, ip string) (*Session, error) {
	return nil, nil
}

func (n *NullAuthentificator) RegisterByName(name, password string) (*Session, error) {
	return nil, nil
}

func (n *NullAuthentificator) SendEmailVerificationCode(callbackURL string, userID int, email Email) error {
	return nil
}

func (n *NullAuthentificator) ValidateEmail(email string, code string) error {
	return nil
}
