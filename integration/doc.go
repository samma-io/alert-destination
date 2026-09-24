// Package integration holds the tests that need real infrastructure: the
// delivery-contract suite and the DynamoDB-backed ledger checks.
//
// Every test file here is behind the `integration` build tag, because they need
// DynamoDB Local running. This file deliberately is NOT: without at least one
// file outside the tag, the package has zero Go files in an ordinary build, and
// anything walking the tree without the tag -- `go build ./...`, `go vet ./...`
// -- fails to compile it.
// The failure reads as "Compilation failure" with no explanation, which is a
// poor thing to leave for the next person.
//
// Run the suite with: make test-integration
package integration
