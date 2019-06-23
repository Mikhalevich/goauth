package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Mikhalevich/argparser"
	"github.com/Mikhalevich/goauth"
	"github.com/Mikhalevich/goauth/db"
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

	a := goauth.NewAuthentificator(pg, pg, goauth.NewCookieSession("test", 5*60))
	if a == nil {
		fmt.Println(a)
	}

	http.HandleFunc("/", rootHandler)
	http.ListenAndServe(":8080", nil)
}
