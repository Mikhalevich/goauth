package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Mikhalevich/argparser"
	"github.com/Mikhalevich/goauth"
	"github.com/Mikhalevich/goauth/db"
)

var (
	auth *goauth.Authentificator
)

type DBParams struct {
	User     string `json:"user"`
	Password string `json:"pwd"`
	DBName   string `json:"db_name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SSLMode  string `json:"sslmode"`
}

func NewDBParams() *DBParams {
	return &DBParams{
		User:     "postgres",
		Password: "",
		DBName:   "Test",
		Host:     "localhost",
		Port:     5432,
		SSLMode:  "disable",
	}
}

func (p DBParams) connectionString() string {
	return fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d sslmode=%s", p.User, p.Password, p.DBName, p.Host, p.Port, p.SSLMode)
}

type Params struct {
	DB DBParams `json:"db"`
}

func NewParams() *Params {
	return &Params{
		DB: *NewDBParams(),
	}
}

func loadParams() (*Params, error) {
	basicParams := NewParams()
	parser := argparser.NewParser()
	params, err, gen := parser.Parse(basicParams)

	if gen {
		return nil, errors.New("Config should be autogenerated")
	}

	return params.(*Params), err
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "root handler...")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	userInfo := NewTemplatePassword()
	renderTemplate := true
	defer func() {
		if renderTemplate {
			if err := userInfo.Execute(w); err != nil {
				log.Println(err)
			}
		}
	}()

	if r.Method != http.MethodPost {
		return
	}

	userInfo.Name = r.FormValue("name")
	userInfo.Password = r.FormValue("password")

	if userInfo.Name == "" {
		userInfo.AddError("name", "Please specify storage name to login")
	}

	if userInfo.Password == "" {
		userInfo.AddError("password", "Please enter password to login")
	}

	if len(userInfo.Errors) > 0 {
		return
	}

	err, session := auth.AuthorizeByName(userInfo.Name, userInfo.Password, r.RemoteAddr)
	if err != nil {
		userInfo.AddError("name", err.Error())
		return
	}

	renderTemplate = false
	cookie := http.Cookie{Name: session.Name, Value: session.Value, Path: "/", Expires: time.Unix(session.Expires, 0), HttpOnly: true}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	userInfo := NewTemplateRegister()
	renderTemplate := true
	defer func() {
		if renderTemplate {
			if err := userInfo.Execute(w); err != nil {
				log.Println(err)
			}
		}
	}()

	if r.Method != http.MethodPost {
		return
	}

	userInfo.Name = r.FormValue("name")
	userInfo.Password = r.FormValue("password")

	if userInfo.Name == "" {
		userInfo.AddError("name", "Please specify storage name to login")
	}

	if userInfo.Password == "" {
		userInfo.AddError("password", "Please enter password to login")
	}

	if len(userInfo.Errors) > 0 {
		return
	}

	err, session := auth.RegisterByName(userInfo.Name, userInfo.Password)
	if err != nil {
		userInfo.AddError("name", err.Error())
		return
	}

	renderTemplate = false
	cookie := http.Cookie{Name: session.Name, Value: session.Value, Path: "/", Expires: time.Unix(session.Expires, 0), HttpOnly: true}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := auth.GetUser(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	params, err := loadParams()
	if err != nil {
		fmt.Println(err)
		return
	}

	pg, err := db.NewPostgres(db.PGParams{DBName: params.DB.DBName, User: params.DB.User, Password: params.DB.Password, Host: params.DB.Host, Port: params.DB.Port, SSLMode: params.DB.SSLMode})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pg.Close()

	auth = goauth.NewAuthentificator(pg, pg, goauth.NewCookieSession("test", 5*60))

	http.Handle("/", checkAuth(http.HandlerFunc(rootHandler)))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/reg", registerHandler)
	http.ListenAndServe(":8080", nil)
}
