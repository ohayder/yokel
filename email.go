package main

import (
	"gopkg.in/mail.v2"
)

type EmailSender interface {
	SendEmail(to, subject, body string) error
}

type GomailSender struct {
	dialer *mail.Dialer
	from   string
}

func NewGomailSender(host string, port int, username, password, from string) *GomailSender {
	dialer := mail.NewDialer(host, port, username, password)
	return &GomailSender{
		dialer: dialer,
		from:   from,
	}
}

func (g *GomailSender) SendEmail(to, subject, body string) error {
	m := mail.NewMessage()
	m.SetHeader("From", g.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return g.dialer.DialAndSend(m)
}