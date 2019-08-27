package goauth

import (
	"time"
)

type Session struct {
	Name    string
	Value   string
	Created int64
	Expires int64
}

func NewSession(name string, value string, expirePeriod int64) *Session {
	ct := time.Now().Unix()

	return &Session{
		Name:    name,
		Value:   value,
		Created: ct,
		Expires: ct + expirePeriod,
	}
}

func (s *Session) IsExpired() bool {
	return s.Expires < time.Now().Unix()
}
