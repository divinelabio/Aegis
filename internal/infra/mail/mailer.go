package mail

import (
	"fmt"
	"net/smtp"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"go.uber.org/zap"
)

type Mailer struct {
	Config config.SMTPConfig
	Logger *zap.Logger
}

func NewMailer(cfg config.SMTPConfig, logger *zap.Logger) *Mailer {
	return &Mailer{
		Config: cfg,
		Logger: logger,
	}
}

func (m *Mailer) SendResetEmail(to string, resetLink string) error {
	subject := "Subject: Aegis Password Reset Request\r\n"
	contentType := "Content-Type: text/plain; charset=UTF-8\r\n"
	from := fmt.Sprintf("From: %s\r\n", m.Config.From)
	toHeader := fmt.Sprintf("To: %s\r\n", to)

	body := fmt.Sprintf(`Hello,

We received a request to reset your password for the Aegis Administration Panel.

Click the link below to set a new password:
%s

If you did not request this, please ignore this email.
Your account remains secure.

Best regards,
Aegis Security Team
`, resetLink)

	msg := []byte(from + toHeader + subject + contentType + "\r\n" + body)

	addr := fmt.Sprintf("%s:%d", m.Config.Host, m.Config.Port)

	// In dev mode (MailHog), Auth might be empty
	var auth smtp.Auth
	if m.Config.Username != "" {
		auth = smtp.PlainAuth("", m.Config.Username, m.Config.Password, m.Config.Host)
	}

	m.Logger.Info("Sending password reset email",
		zap.String("to", to),
		zap.String("host", addr),
	)

	err := smtp.SendMail(addr, auth, m.Config.From, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
