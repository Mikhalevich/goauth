package db

import (
	"fmt"
	"testing"

	"github.com/Mikhalevich/goauth"
)

var (
	pg *Postgres
)

func init() {
	var err error
	pg, err = NewPostgres(PGParams{DBName: "auth", User: "postgres", Password: "123456", Host: "localhost", Port: 5432, SSLMode: "disable"})
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = pg.db.Exec("DELETE FROM Users")
	if err != nil {
		fmt.Println(err)
		return
	}
}

func BenchmarkAddUser(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u := &goauth.User{
			Name:     fmt.Sprintf("test_user_%d", i),
			Pwd:      fmt.Sprintf("test_user_pwd_%d", i),
			Emails:   []goauth.Email{goauth.Email{Email: fmt.Sprintf("test_user_%d@gmail.com", i), Verified: true, Primary: false}},
			Sessions: []goauth.Session{goauth.Session{Name: fmt.Sprintf("test_user_session_%d", i), Value: fmt.Sprintf("test_user_session_value_%d", i), Expires: int64(i)}},
		}
		if err := pg.Add(u); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetUserByName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("test_user_%d", i)
		if _, err := pg.GetByName(name); (err != nil) && (err != goauth.ErrNotExists) {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetUserByNameNotExisting(b *testing.B) {
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("no_such_user_test_user_%d", i)
		if _, err := pg.GetByName(name); (err != nil) && (err != goauth.ErrNotExists) {
			b.Fatal(err)
		}
	}
}
