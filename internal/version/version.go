// Package version holds the build version of Aegis-Recon. The default is the
// last released version; release builds override it at link time with:
//
//	-ldflags "-X github.com/RodriguesWall/aegis-recon/internal/version.Version=<v>"
//
// The Makefile injects `git describe --tags --always --dirty`. Bump this default
// whenever a version is closed, following SemVer: PATCH for fixes only, MINOR for
// backward-compatible features (e.g. 1.0.4 -> 1.1.0), MAJOR for breaking changes.
package version

// Version is the build version. Overridden via -ldflags at build time.
var Version = "1.1.0"
