package testutil

import (
	"fmt"
	"path/filepath"
	"testing"
)

// fakeCommand is a command/script to be run by tests for "entrypoint" commands. Each command touches
// a "ready file" when the command has started and done any setup. This is important for the tests
// to ensure the command subcommand has started to avoid races. For example, certain tests should not
// proceed until traps for sigint and sigterm have been setup.
type FakeCommand struct {
	// The command to run.
	Command string
	// Check this file exists to check the command is ready.
	ReadyFile string
}

// FakeCommandWithTraps a script used to validate our "entrypoint" commands:
// * When a sigint is received, it exits with code 42
// * When a sigterm is received, it exits with code 55
// * It sleeps for 120 seconds (long enough for tests, but not so long that it holds up CI)
//
// Why not just a simple 'sleep 120'?
// * Bash actually ignores SIGINT by default (note: CTRL-C sends SIGINT to the process group, not just the parent)
// * Tests can be run in different places, so /bin/sh could be any shell with different behavior.
// Why a background process + wait? Why not just a trap + sleep?
// * The sleep blocks the trap. Traps are not executed until the current command completes, except for `wait`.
func FakeCommandWithTraps(t *testing.T, sleep int) FakeCommand {
	dir := TempDir(t)
	readyFile := filepath.Join(dir, "proc-ready")
	return FakeCommand{
		ReadyFile: readyFile,
		Command: fmt.Sprintf(`sleep %d &
export SLEEP_PID=$!
trap "{ echo 'target command was interrupted'; kill $SLEEP_PID; exit 42; }" INT
trap "{ echo 'target command was terminated'; kill $SLEEP_PID; exit 55; }" TERM
touch %s
wait $SLEEP_PID
`, sleep, readyFile),
	}
}

// SimpleFakeCommand sleeps for a given number of seconds.
func SimpleFakeCommand(t *testing.T, sleep int) FakeCommand {
	dir := TempDir(t)
	readyFile := filepath.Join(dir, "proc-ready")
	return FakeCommand{
		Command: fmt.Sprintf(`touch %s
sleep %d`, readyFile, sleep),
		ReadyFile: readyFile,
	}
}
