package goauth

import gomail "gopkg.in/gomail.v2"

type GomailSender struct {
	Host     string
	Port     int
	From     string
	Password string
}

func (gms *GomailSender) Sent(emailTo string, contentType string, body string) error {
	m := gomail.NewMessage()
	m.SetAddressHeader("From", gms.From, "")
	m.SetAddressHeader("To", emailTo, "")
	m.SetHeader("Subject", "Email validation")
	m.SetBody(contentType, body)

	d := gomail.NewPlainDialer(gms.Host, gms.Port, gms.From, gms.Password)
	return d.DialAndSend(m)
}
