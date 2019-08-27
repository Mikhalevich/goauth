package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/Mikhalevich/goauth"
)

type CookieSession struct {
	Name         string
	ExpirePeriod int64
}

func NewCookieSession(name string, period int64) *CookieSession {
	return &CookieSession{
		Name:         name,
		ExpirePeriod: period,
	}
}

func (cs *CookieSession) Create() goauth.Session {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return *goauth.NewSession(cs.Name, base64.URLEncoding.EncodeToString(bytes), cs.ExpirePeriod)
}

func (cs *CookieSession) Find(r *http.Request) (goauth.Session, error) {
	for _, cook := range r.Cookies() {
		if cook.Name != cs.Name {
			continue
		}

		return goauth.Session{
			Name:    cs.Name,
			Value:   cook.Value,
			Expires: cook.Expires.Unix(),
		}, nil
	}

	return goauth.Session{}, goauth.ErrNotExists
}
