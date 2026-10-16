package internal

import (
	"testing"
)

// A2 must stay silent: a non-_test.go Go file importing "testing" is a test helper.
func AddExamples(t *testing.T) {
	clients := []struct{ ID, Secret string }{
		{ID: "encoded:client", Secret: "encoded&password"},
		{ID: "name-new", Secret: "secret-new"},
	}
	_ = clients
}
