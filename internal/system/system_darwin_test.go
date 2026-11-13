package system

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// After a rotation, what the process writes straight to fd 2, such as a panic
// trace, goes to the new file with the log. The test runs itself again with
// stderr on a temp file, since it moves the child's fd 2.
func TestOnStdioMovesFd2(t *testing.T) {
	if path := os.Getenv("HALLPASS_TEST_FD2_LOG"); path != "" {
		w := newFollowWriter(path, os.Stderr)
		w.replace = onStdio
		_, _ = w.Write([]byte("one\n"))
		rotate(t, path, true)
		_, _ = w.Write([]byte("two\n"))
		_, _ = syscall.Write(2, []byte("raw\n"))
		return
	}
	path := t.TempDir() + "/hallpass.log"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOnStdioMovesFd2$")
	cmd.Env = append(os.Environ(), "HALLPASS_TEST_FD2_LOG="+path)
	cmd.Stderr = f
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, path+".0", "one\n")
	// The child's test framework prints PASS on stdout, which moved too.
	assertFile(t, path, "two\nraw\nPASS\n")
}
