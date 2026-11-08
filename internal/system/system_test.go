package system

import (
	"os"
	"testing"
)

func TestRootControlledRejectsUserDirs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if err := RootControlled(t.TempDir()); err == nil {
		t.Fatal("accepted a directory the test user owns")
	}
	if err := RootControlled("/usr/bin"); err != nil {
		t.Fatalf("rejected /usr/bin: %v", err)
	}
}
