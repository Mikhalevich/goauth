package goauth

import "net/http"

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

func (cs *CookieSession) Create() Session {
	return *NewSession(cs.Name, cs.ExpirePeriod)
}

func (cs *CookieSession) Find(r *http.Request) (Session, error) {
	for _, cook := range r.Cookies() {
		if cook.Name != cs.Name {
			continue
		}

		return Session{
			Name:    cs.Name,
			Value:   cook.Value,
			Expires: cook.Expires.Unix(),
		}, nil
	}

	return Session{}, ErrNotExists
}
