// Generate markdown from the JSON schema for the Consul ECS config.
//
// You can use the Makefile in the root of the repository to run this script.
// Usage:
//    make reference-configuration
//    make reference-configuration consul=<path-to-consul-repo>
//    go run . > ../../../website/content/docs/ecs/configuration-reference.mdx
//
// This generates configuration from the schema.json, recursively:
// - First, write the preamble to stdout (see ./preamble.mdx).
// - For each object or array type in schema.json, render a template to stdout (see ./properties.tpl)
//
// Edit the <repoRoot>/config/schema.json to modify descriptions.
// After editing the schema.json, re-run this script to update the Consul ECS documentation.
// The generated markdown should be included in ECS docs in the Consul repo.

package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/hashicorp/consul-ecs/config"
)

var (
	//go:embed preamble.mdx
	preamble string

	//go:embed properties.tpl
	propertiesTemplate string

	// Markdown heading prefixes
	depthToHeading = []string{
		0: "#",
		1: "#",
		2: "##",
		3: "###",
		4: "####",
		5: "#####",
		6: "######",
	}
)

// getTemplate returns a template for a section of markdown, with the given path as the heading.
func getTemplate(path string) *template.Template {
	// Generate heading based on path depth: "## `service.checks`"
	depth := strings.Count(path, ".")
	heading := depthToHeading[depth]
	if path == "" {
		heading += " Top-level fields"
	} else {
		heading += " `" + path + "`"
	}

	templateString := heading + "\n\n" + propertiesTemplate
	tpl, err := template.New(path).Parse(templateString)
	if err != nil {
		log.Fatal(err)
	}
	return tpl
}

// RenderTemplates walks through the schema recursively to generate markdown.
// It writes directly to the provided io.Writer.
func RenderTemplates(path string, schema *Schema, wr io.Writer) {
	if schema.Type[0] == "array" {
		itemSchema := schema.Items
		RenderTemplates(path, itemSchema, wr)
		return
	}

	if schema.Type[0] == "object" && schema.Properties != nil {
		tpl := getTemplate(path)

		schema.Path = path
		err := tpl.Execute(wr, schema)
		if err != nil {
			log.Fatal(err)
		}

		for _, field := range sortedKeys(schema.Properties) {
			propSchema := schema.Properties[field]
			propPath := strings.Trim(path+"."+field, ".")
			RenderTemplates(propPath, propSchema, wr)
		}
	}
}

func sortedKeys(props map[string]*Schema) []string {
	result := make([]string, 0, len(props))
	for k := range props {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func main() {
	var schema Schema
	if err := json.Unmarshal([]byte(config.Schema), &schema); err != nil {
		log.Fatal(err)
	}

	outWriter := os.Stdout

	_, _ = fmt.Fprintln(outWriter, preamble)
	RenderTemplates("", &schema, outWriter)
}
