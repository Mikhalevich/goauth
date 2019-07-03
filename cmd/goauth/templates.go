package main

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path"
	"path/filepath"
)

func templatePath(name string) string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}

	return path.Join(filepath.Dir(executable), "html", name)
}

var (
	pcTemplates = template.Must(template.New("fileSharing").ParseFiles(
		templatePath("login.html"),
		templatePath("register.html")))
)

type TemplateBase struct {
	Name   string
	Errors map[string]string
}

func NewTemplateBase(name string) *TemplateBase {
	return &TemplateBase{
		Name:   name,
		Errors: make(map[string]string),
	}
}

func (t *TemplateBase) AddError(name string, errorValue string, params ...interface{}) {
	t.Errors[name] = fmt.Sprintf(errorValue, params...)
}

func (t *TemplateBase) ExecuteTemplate(wr io.Writer, data interface{}) error {
	return pcTemplates.ExecuteTemplate(wr, t.Name, data)
}

type TemplatePassword struct {
	TemplateBase
	Name     string
	Password string
}

func NewTemplatePassword() *TemplatePassword {
	return &TemplatePassword{
		TemplateBase: *NewTemplateBase("login.html"),
	}
}

func (t *TemplatePassword) Execute(wr io.Writer) error {
	return t.TemplateBase.ExecuteTemplate(wr, *t)
}

type TemplateRegister struct {
	TemplateBase
	Name     string
	Password string
}

func NewTemplateRegister() *TemplateRegister {
	return &TemplateRegister{
		TemplateBase: *NewTemplateBase("register.html"),
	}
}

func (t *TemplateRegister) Execute(wr io.Writer) error {
	return t.TemplateBase.ExecuteTemplate(wr, *t)
}
