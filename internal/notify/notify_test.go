package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/secret"
	"github.com/RodriguesWall/aegis-recon/internal/store/memory"
)

type capture struct {
	calls   int
	cfg     SMTPConfig
	subject string
	body    string
}

func (c *capture) send(cfg SMTPConfig, subject, body string) error {
	c.calls++
	c.cfg, c.subject, c.body = cfg, subject, body
	return nil
}

func setup(t *testing.T, settings map[string]string) (*Service, *capture, *memory.Store) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P"})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Name: "acme.example", Type: model.AssetDomain})
	for k, v := range settings {
		st.SetSetting(ctx, k, v)
	}
	cap := &capture{}
	return New(st, nil).WithEmailSender(cap.send), cap, st
}

func scan(trigger string) *model.Scan {
	return &model.Scan{ID: "s1", AssetID: "a1", Status: model.StatusCompleted, Trigger: trigger}
}

func findings() []model.Finding {
	return []model.Finding{
		{Scanner: "httpprobe", Target: model.Target{Host: "acme.example", Port: 443}, Severity: model.SeverityHigh, Title: "admin exposed"},
	}
}

func TestDisabledNoSend(t *testing.T) {
	s, cap, _ := setup(t, map[string]string{"notify_email_enabled": "false"})
	s.ScanComplete(context.Background(), scan(model.TriggerScheduled), findings())
	if cap.calls != 0 {
		t.Fatal("must not send when disabled")
	}
}

func TestScopeScheduledSkipsManual(t *testing.T) {
	s, cap, _ := setup(t, map[string]string{"notify_email_enabled": "true", "notify_scope": "scheduled", "smtp_host": "h", "smtp_port": "25", "smtp_to": "a@b.c"})
	s.ScanComplete(context.Background(), scan(model.TriggerManual), findings())
	if cap.calls != 0 {
		t.Fatal("scope=scheduled must skip a manual scan")
	}
	s.ScanComplete(context.Background(), scan(model.TriggerScheduled), findings())
	if cap.calls != 1 {
		t.Fatal("scope=scheduled must send a scheduled scan")
	}
}

func TestScopeAllSendsManual(t *testing.T) {
	s, cap, _ := setup(t, map[string]string{"notify_email_enabled": "true", "notify_scope": "all", "smtp_host": "h", "smtp_port": "25", "smtp_to": "a@b.c"})
	s.ScanComplete(context.Background(), scan(model.TriggerManual), findings())
	if cap.calls != 1 {
		t.Fatal("scope=all must send a manual scan")
	}
	if !strings.Contains(cap.subject, "acme.example") {
		t.Fatalf("subject missing asset: %q", cap.subject)
	}
	if !strings.Contains(cap.body, "admin exposed") || !strings.Contains(cap.body, "high") {
		t.Fatalf("body missing finding/severity: %q", cap.body)
	}
}

func TestWebhookSends(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P"})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Name: "acme.example", Type: model.AssetDomain})
	for k, v := range map[string]string{
		"notify_webhook_enabled": "true", "notify_scope": "all", "webhook_url": "https://hook.example/x",
	} {
		st.SetSetting(ctx, k, v)
	}
	var got WebhookPayload
	calls := 0
	s := New(st, nil).WithWebhookSender(func(url string, p WebhookPayload) error {
		calls++
		got = p
		return nil
	})
	s.ScanComplete(ctx, scan(model.TriggerManual), findings())
	if calls != 1 {
		t.Fatalf("expected 1 webhook call, got %d", calls)
	}
	if got.Event != "scan.completed" || got.Asset != "acme.example" || got.Findings != 1 {
		t.Fatalf("payload fields wrong: %+v", got)
	}
	if got.Severity["high"] != 1 {
		t.Fatalf("severity map wrong: %+v", got.Severity)
	}
	if got.Text == "" {
		t.Fatal("payload text summary empty")
	}
}

func TestNeitherChannelNoSend(t *testing.T) {
	s, cap, _ := setup(t, map[string]string{"notify_email_enabled": "false", "notify_webhook_enabled": "false"})
	s.ScanComplete(context.Background(), scan(model.TriggerScheduled), findings())
	if cap.calls != 0 {
		t.Fatal("no channel enabled must not send")
	}
}

func TestDecryptsSMTPPass(t *testing.T) {
	enc, _ := secret.Encrypt("hunter2")
	s, cap, _ := setup(t, map[string]string{
		"notify_email_enabled": "true", "notify_scope": "all",
		"smtp_host": "h", "smtp_port": "25", "smtp_user": "u", "smtp_pass": enc, "smtp_to": "a@b.c",
	})
	s.ScanComplete(context.Background(), scan(model.TriggerManual), findings())
	if cap.cfg.Pass != "hunter2" {
		t.Fatalf("smtp pass not decrypted into cfg: %q", cap.cfg.Pass)
	}
}
