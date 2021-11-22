package appentrypoint

func (c *Command) Help() string {
	return ""
}

func (c *Command) Synopsis() string {
	return "Entrypoint for running Envoy in ECS"
}
