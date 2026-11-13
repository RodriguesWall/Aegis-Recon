// Package version holds the build version of Aegis-Recon. The default is "dev";
// release builds override it at link time with:
//
//	-ldflags "-X github.com/RodriguesWall/aegis-recon/internal/version.Version=<v>"
//
// The Makefile injects `git describe --tags --always --dirty`.
package version

// Version is the build version. Overridden via -ldflags at build time.
var Version = "dev"
