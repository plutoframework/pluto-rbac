package rbac_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestExecutionCannotBeForgedByConsumer(t *testing.T) {
	command := exec.Command("go", "test", "./testdata/execution-forgery")

	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("forged private capability compiled")
	}

	if !strings.Contains(string(output), "unexported field state") {
		t.Fatalf("unexpected compile failure: %s", output)
	}
}
