package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/secret"
	"github.com/RodriguesWall/aegis-recon/internal/store"
)

// EmailSender delivers one email; injectable for tests.
type EmailSender func(cfg SMTPConfig, subject, body string) error

// Service decides whether to notify and dispatches the configured channels. It
// reads its config from the persisted settings every time, so changes take
// effect without a restart.
type Service struct {
	store     store.Store
	logger    *slog.Logger
	emailSend EmailSender
}

// New builds a notify Service backed by the store's settings.
func New(st store.Store, logger *slog.Logger) *Service {
	return &Service{store: st, logger: logger, emailSend: sendEmail}
}

// WithEmailSender overrides the email transport (tests).
func (s *Service) WithEmailSender(fn EmailSender) *Service {
	s.emailSend = fn
	return s
}

// ScanComplete notifies about a completed scan, honoring the configured channels
// and scope. Best-effort: failures are logged, never returned.
func (s *Service) ScanComplete(ctx context.Context, scan *model.Scan, findings []model.Finding) {
	set, err := s.store.AllSettings(ctx)
	if err != nil {
		s.logf("notify: load settings", "err", err)
		return
	}
	if set["notify_email_enabled"] != "true" {
		return
	}
	// Scope: "scheduled" (default) notifies only scheduled scans; "all" notifies
	// manual ones too.
	scope := set["notify_scope"]
	if scope == "" {
		scope = model.TriggerScheduled
	}
	if scope == model.TriggerScheduled && scan.Trigger != model.TriggerScheduled {
		return
	}

	asset := scan.AssetID
	if a, err := s.store.GetAsset(ctx, scan.AssetID); err == nil {
		asset = a.Name
	}
	subject, body := scanEmail(asset, scan, findings)

	cfg := SMTPConfig{
		Host:     set["smtp_host"],
		Port:     set["smtp_port"],
		User:     set["smtp_user"],
		From:     set["smtp_from"],
		To:       set["smtp_to"],
		Security: set["smtp_security"],
	}
	if enc := set["smtp_pass"]; enc != "" {
		if dec, err := secret.Decrypt(enc); err == nil {
			cfg.Pass = dec
		} else {
			s.logf("notify: decrypt smtp_pass", "err", err)
		}
	}

	if err := s.emailSend(cfg, subject, body); err != nil {
		s.logf("notify: send email", "scan", scan.ID, "err", err)
		return
	}
	s.logf("notify: email sent", "scan", scan.ID, "asset", asset)
}

func (s *Service) logf(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Info(msg, args...)
	}
}

// scanEmail builds the subject and plain-text body for a completed scan.
func scanEmail(asset string, scan *model.Scan, findings []model.Finding) (string, string) {
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	subject := fmt.Sprintf("Aegis-Recon: scan completed — %s (%d findings)", asset, len(findings))

	var b strings.Builder
	fmt.Fprintf(&b, "Scan completed for %s\n", asset)
	fmt.Fprintf(&b, "Status: %s\n", scan.Status)
	if scan.CompletedAt != nil {
		fmt.Fprintf(&b, "Completed: %s\n", scan.CompletedAt.Format("2006-01-02 15:04:05 MST"))
	}
	b.WriteString("\nSeverity:\n")
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		fmt.Fprintf(&b, "  %-8s %d\n", sev, counts[sev])
	}

	if len(findings) == 0 {
		b.WriteString("\nNo findings — clean.\n")
		return subject, b.String()
	}

	// Top findings by severity (cap 10).
	top := append([]model.Finding(nil), findings...)
	sort.SliceStable(top, func(i, j int) bool { return top[i].Severity.Rank() > top[j].Severity.Rank() })
	if len(top) > 10 {
		top = top[:10]
	}
	b.WriteString("\nTop findings:\n")
	for _, f := range top {
		host := f.Target.Host
		if host == "" {
			host = f.Target.Domain
		}
		fmt.Fprintf(&b, "  [%s] %s — %s\n", f.Severity, host, f.Title)
	}
	return subject, b.String()
}
