// Command aegis-mcp is a read-only MCP server over the Aegis-Recon database. It
// exposes query tools (projects, assets, scans, findings, stats) to an MCP
// client (e.g. Claude Desktop/Code) over stdio, so the security posture can be
// queried in natural language. Read-only: no scan triggering or triage changes.
//
//	AEGIS_DB=db/aegis.db aegis-mcp
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/RodriguesWall/aegis-recon/internal/config"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/report"
	"github.com/RodriguesWall/aegis-recon/internal/store"
	"github.com/RodriguesWall/aegis-recon/internal/store/sqlite"
	"github.com/RodriguesWall/aegis-recon/internal/version"
)

func main() {
	cfg, err := config.Resolve(envOr("AEGIS_CONFIG", "aegis.yaml"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if dir := filepath.Dir(cfg.DB); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	st, err := sqlite.Open(cfg.DB)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	s := server.NewMCPServer("aegis-recon", version.Version)
	registerTools(s, st)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("mcp serve: %v", err)
	}
}

func registerTools(s *server.MCPServer, st store.Store) {
	s.AddTool(mcp.NewTool("list_projects",
		mcp.WithDescription("List all projects.")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return jsonResult(st.ListProjects(ctx))
		})

	s.AddTool(mcp.NewTool("list_assets",
		mcp.WithDescription("List the services (assets) of a project."),
		mcp.WithString("project", mcp.Required(), mcp.Description("Project ID"))),
		func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return jsonResult(st.ListAssets(ctx, r.GetString("project", "")))
		})

	s.AddTool(mcp.NewTool("list_scans",
		mcp.WithDescription("List the scans of a service (asset), newest first."),
		mcp.WithString("asset", mcp.Required(), mcp.Description("Asset ID"))),
		func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return jsonResult(st.ListScans(ctx, r.GetString("asset", "")))
		})

	s.AddTool(mcp.NewTool("get_scan",
		mcp.WithDescription("Get a scan with its findings (incl. remediation)."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Scan ID"))),
		func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id := r.GetString("id", "")
			scan, err := st.GetScan(ctx, id)
			if err != nil {
				return mcp.NewToolResultError("scan not found"), nil
			}
			fs, err := st.ListFindings(ctx, id)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(map[string]any{"scan": scan, "findings": enrich(fs)}, nil)
		})

	s.AddTool(mcp.NewTool("get_findings",
		mcp.WithDescription("Current findings across all projects (latest scan per service).")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return jsonResult(st.CurrentFindings(ctx))
		})

	s.AddTool(mcp.NewTool("get_stats",
		mcp.WithDescription("Aggregate posture: totals, severity counts and triage breakdown.")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return jsonResult(stats(ctx, st))
		})
}

// enrich adds a remediation hint to each finding for the LLM.
func enrich(fs []model.Finding) []map[string]any {
	out := make([]map[string]any, len(fs))
	for i, f := range fs {
		out[i] = map[string]any{
			"scanner": f.Scanner, "severity": f.Severity, "title": f.Title,
			"target": f.Target, "evidence": f.Evidence,
			"fingerprint": f.Fingerprint(), "remediation": report.Remediation(f),
		}
	}
	return out
}

func stats(ctx context.Context, st store.Store) (map[string]any, error) {
	cur, err := st.CurrentFindings(ctx)
	if err != nil {
		return nil, err
	}
	triage, err := st.ListAllTriage(ctx)
	if err != nil {
		return nil, err
	}
	projects, _ := st.ListProjects(ctx)
	tri := map[string]model.TriageStatus{}
	for _, t := range triage {
		tri[t.AssetID+"\x00"+t.Fingerprint] = t.Status
	}
	sev := map[string]int{}
	open, fp, acc, fixed := 0, 0, 0, 0
	for _, cf := range cur {
		sev[string(cf.Severity)]++
		switch tri[cf.AssetID+"\x00"+cf.Fingerprint] {
		case model.TriageFalsePositive:
			fp++
		case model.TriageAcceptedRisk:
			acc++
		case model.TriageFixed:
			fixed++
		default:
			open++
		}
	}
	return map[string]any{
		"projects": len(projects),
		"findings": len(cur),
		"severity": sev,
		"triage":   map[string]int{"open": open, "false_positive": fp, "accepted_risk": acc, "fixed": fixed},
	}, nil
}

// jsonResult marshals v to a text result, surfacing any carried error.
func jsonResult(v any, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	b, merr := json.MarshalIndent(v, "", "  ")
	if merr != nil {
		return mcp.NewToolResultError(merr.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
