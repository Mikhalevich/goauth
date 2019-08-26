package email

import (
	"fmt"
	"net/smtp"
)

type EmailSender struct {
	Host     string
	Port     string
	From     string
	Password string
}

func (es *EmailSender) Sent(emailTo string, contentType string, body string) error {
	auth := smtp.PlainAuth("", es.From, es.Password, es.Host)
	msg := fmt.Sprintf("From: %s\r\n", es.From) +
		fmt.Sprintf("To: %s\r\n", emailTo) +
		"MIME-Version: 1.0\r\n" +
		fmt.Sprintf("Content-type: %s\r\n", contentType) +
		"Subject: Email validation\r\n\r\n" +
		body + "\r\n"
	return smtp.SendMail(fmt.Sprintf("%s:%s", es.Host, es.Port), auth, es.From, []string{emailTo}, []byte(msg))
}
