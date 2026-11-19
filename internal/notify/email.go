// Package notify sends notifications (email, webhook) about scan events,
// configured through the persisted settings.
package notify

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPConfig is the mail transport config, read from settings.
type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Pass     string
	From     string
	To       string // one or more addresses, comma-separated
	Security string // "ssl" (implicit TLS), "starttls", or "none"
}

func (c SMTPConfig) recipients() []string {
	var out []string
	for _, a := range strings.Split(c.To, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// sendEmail delivers a plain-text message. It supports implicit TLS ("ssl"),
// STARTTLS, and plaintext ("none"). Auth is used only when a user is set.
func sendEmail(cfg SMTPConfig, subject, body string) error {
	if cfg.Host == "" || cfg.Port == "" {
		return errors.New("notify: smtp host/port not set")
	}
	to := cfg.recipients()
	if len(to) == 0 {
		return errors.New("notify: no recipients")
	}
	addr := cfg.Host + ":" + cfg.Port
	msg := buildMessage(cfg.From, to, subject, body)

	var auth smtp.Auth
	if cfg.User != "" {
		auth = smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	}

	switch strings.ToLower(cfg.Security) {
	case "ssl", "tls":
		return sendImplicitTLS(addr, cfg.Host, auth, cfg.From, to, msg)
	case "starttls", "":
		return sendStartTLS(addr, cfg.Host, auth, cfg.From, to, msg)
	case "none":
		return smtp.SendMail(addr, auth, cfg.From, to, msg)
	default:
		return fmt.Errorf("notify: unknown smtp security %q", cfg.Security)
	}
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("notify: tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	return deliver(c, auth, from, to, msg)
}

func sendStartTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("notify: dial: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("notify: starttls: %w", err)
		}
	}
	return deliver(c, auth, from, to, msg)
}

func deliver(c *smtp.Client, auth smtp.Auth, from string, to []string, msg []byte) error {
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("notify: auth: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
