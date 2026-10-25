package services

import (
	"fmt"
	"log"

	"github.com/resend/resend-go/v4"
)

type EmailService struct {
	client *resend.Client
	from   string
	appURL string
}

func NewEmailService(apiKey, from, appURL string) *EmailService {
	return &EmailService{
		client: resend.NewClient(apiKey),
		from:   from,
		appURL: appURL,
	}
}

// SendVerification sends an email with a verification link.
func (s *EmailService) SendVerification(to, token string) error {
	link := fmt.Sprintf("%s/verify-email?token=%s", s.appURL, token)
	params := &resend.SendEmailRequest{
		From:    s.from,
		To:      []string{to},
		Subject: "Verify your email",
		Html:    fmt.Sprintf(`<p>Click the link below to verify your email address (valid for 24 hours):</p><p><a href="%s">Verify Email</a></p>`, link),
	}
	sent, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	log.Printf("verification email sent: id=%s to=%s", sent.Id, to)
	return nil
}

// SendPasswordReset sends an email with a deep link + token.
func (s *EmailService) SendPasswordReset(to, token string) error {
  // Deep link for Android app
  deepLink := fmt.Sprintf("vpn://reset-password?token=%s", token)
  // Web fallback (user can copy token)
  webURL := fmt.Sprintf("%s/reset-password?token=%s", s.appURL, token)

  html := fmt.Sprintf(`
    <p>သင့် password ကို ပြန်လည် သတ်မှတ်ရန် အောက်ပါ link ကို နှိပ်ပါ (၁ နာရီ သက်တမ်း):</p>
    <p><a href="%s">Reset Password (App ဖွင့်မယ်)</a></p>
    <p>သို့မဟုတ် web link:</p>
    <p><a href="%s">%s</a></p>
    <hr>
    <p>App ထဲက "Token ကိုယ်တိုင် ထည့်မယ်" screen မှာ ဤ token ကို ထည့်ပါ:</p>
    <p style="font-family:monospace;background:#eee;padding:8px;">%s</p>
  `, deepLink, webURL, webURL, token)

  params := &resend.SendEmailRequest{
    From:    s.from,
    To:      []string{to},
    Subject: "VPN — Password Reset",
    Html:    html,
  }
  sent, err := s.client.Emails.Send(params)
  if err != nil {
    return fmt.Errorf("send password reset email: %w", err)
  }
  log.Printf("password reset email sent: id=%s to=%s", sent.Id, to)
  return nil
}
