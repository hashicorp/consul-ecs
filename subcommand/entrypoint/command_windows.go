//go:build windows
// +build windows

package entrypoint

// Process handling is different on Windows, and since we intend for this to be the entrypoint
// of a Docker container, we only need to support Linux.
func (c *Command) Run(args []string) int {
	c.UI.Error("not implemented on Windows")
	return 1
}
