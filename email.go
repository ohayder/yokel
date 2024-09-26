package main

import (
	"fmt"
	"gopkg.in/mail.v2"
	"net/smtp"
)

type EmailSender interface {
	SendEmail(to, subject, body string) error
}

type GomailSender struct {
	dialer *mail.Dialer
	from   string
}

func NewGomailSender(host string, port int, username, password, from string) (EmailSender, error) {
	if host == "" || port == 0 || username == "" || password == "" || from == "" {
		return nil, fmt.Errorf("incomplete SMTP configuration")
	}

	dialer := mail.NewDialer(host, port, username, password)
	
	// Test the connection
	client, err := smtp.Dial(fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %v", err)
	}
	client.Close()

	return &GomailSender{
		dialer: dialer,
		from:   from,
	}, nil
}

func (g *GomailSender) SendEmail(to, subject, body string) error {
	m := mail.NewMessage()
	m.SetHeader("From", g.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := g.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}