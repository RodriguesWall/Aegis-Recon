// Package version holds the build version of Aegis-Recon. The default is the
// last released version; release builds override it at link time with:
//
//	-ldflags "-X github.com/RodriguesWall/aegis-recon/internal/version.Version=<v>"
//
// The Makefile injects `git describe --tags --always --dirty`. Bump this default
// whenever a version is closed (e.g. 1.0.2 -> 1.0.3).
package version

// Version is the build version. Overridden via -ldflags at build time.
var Version = "1.0.2"
