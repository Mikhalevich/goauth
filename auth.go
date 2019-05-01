package goauth

import "net/http"

const (
	NO_COOKIE = iota
	STATIC_COOKIE
	USER_NAME
)

type cookieComparator struct {
	cookType int
	name     string
}

func (cc *cookieComparator) compare(cookName, userName string) bool {
	switch cc.cookType {
	case NO_COOKIE:
		return false
	case STATIC_COOKIE:
		return cookName == cc.name
	case USER_NAME:
		return cookName == userName
	}
}

func newCookieComparator(ct int, cn string) *cookieComparator {
	return &cookieComparator{
		cookType: ct,
		name:     cn,
	}
}

type Authentificator struct {
	db Userer
	cc *cookieComparator
}

func NewAuthentificator(userDB Userer, cookType int, cookName string) *Authentificator {
	return &Authentificator{
		db: userDB,
		cc: newCookieComparator(cookType, cookName),
	}
}

func (a *Authentificator) IsAuthorized(name string, cookies []*http.Cookie) bool {
	user, err := a.db.UserByName(name)
	if err != nil {
		return false
	}

	for _, cook := range cookies {
		if a.cc.compare(cook.Name, name) {
			session, err := user.Session(cook.Value)
			if err != nil {
				return false
			}

			if session.IsExpired() {
				return false
			}

			return true
		}
	}

	return false
}
