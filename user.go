package goauth

type User struct {
	ID       int
	Name     string
	Pwd      string
	Emails   []Email
	Sessions []Session
}

func (u *User) Session(value string) (Session, error) {
	for _, session := range u.Sessions {
		if session.Value == value {
			return session, nil
		}
	}
	return Session{}, ErrNotExists
}

func (u *User) Email(address string) (Email, error) {
	for _, e := range u.Emails {
		if e.Email == address {
			return e, nil
		}
	}

	return Email{}, ErrNotExists
}
