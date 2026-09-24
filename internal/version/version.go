// Package version carries the build's version string.
package version

// Version is set at link time by the Makefile and the release workflow:
//
//	-ldflags "-X github.com/samma-io/alert-destination/internal/version.Version=v1.2.3"
//
// A build without it reports "dev".
var Version = "dev"

// UserAgent is the header value this service presents to the destinations it
// posts to, so an operator on the receiving side can tell which build called.
func UserAgent() string { return "samma-io-alert-destination/" + Version }
