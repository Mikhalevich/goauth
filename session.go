package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"time"
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
