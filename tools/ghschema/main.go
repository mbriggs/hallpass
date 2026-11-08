// Command ghschema replaces hallpass's embedded copy of GitHub's GraphQL
// schema with the one GitHub publishes, and prints what changed by type and
// field, since the SDL diff is mostly descriptions.
//
//	go run ./tools/ghschema         # fetch, write, report
//	go run ./tools/ghschema -check  # report only
//
// The report's first two sections need review before the new schema ships,
// because they're fields hallpass may now let agents read in an allowed
// repo. New roots and mutations are refused until a policy table names
// them.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

const embedded = "internal/policy/schema/github.graphql"

func main() {
	url := flag.String("url", "https://docs.github.com/public/fpt/schema.docs.graphql", "where GitHub publishes the schema")
	check := flag.Bool("check", false, "report changes without writing the schema")
	flag.Parse()

	oldSDL, err := os.ReadFile(embedded)
	if err != nil {
		log.Fatal(err)
	}
	newSDL, err := fetch(*url)
	if err != nil {
		log.Fatal(err)
	}
	oldS, err := gqlparser.LoadSchema(&ast.Source{Name: "old", Input: string(oldSDL)})
	if err != nil {
		log.Fatalf("embedded schema: %v", err)
	}
	newS, err := gqlparser.LoadSchema(&ast.Source{Name: "new", Input: string(newSDL)})
	if err != nil {
		log.Fatalf("%s: %v", *url, err)
	}

	if string(oldSDL) == string(newSDL) {
		fmt.Println("The embedded schema matches GitHub's.")
		return
	}
	report(oldS, newS)
	if *check {
		return
	}
	if err := os.WriteFile(embedded, newSDL, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nWrote %s. Run go test ./internal/policy before committing.\n", embedded)
}

func fetch(url string) ([]byte, error) {
	c := &http.Client{Timeout: time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func report(oldS, newS *ast.Schema) {
	var readable, edges, roots, mutations, removed, types []string
	for _, name := range sortedTypes(newS) {
		d := newS.Types[name]
		old := oldS.Types[name]
		if old == nil {
			types = append(types, "+ "+name)
		}
		if d.Kind != ast.Object && d.Kind != ast.Interface {
			continue
		}
		for _, f := range d.Fields {
			if old != nil && old.Fields.ForName(f.Name) != nil {
				continue
			}
			line := fmt.Sprintf("+ %s.%s: %s", name, f.Name, f.Type)
			kind := newS.Types[f.Type.Name()].Kind
			switch {
			case name == "Query":
				roots = append(roots, line)
			case name == "Mutation":
				mutations = append(mutations, line)
			case kind == ast.Scalar || kind == ast.Enum:
				readable = append(readable, line)
			default:
				edges = append(edges, line)
			}
		}
	}
	for _, name := range sortedTypes(oldS) {
		d := oldS.Types[name]
		nd := newS.Types[name]
		if nd == nil {
			removed = append(removed, "- "+name)
			continue
		}
		for _, f := range d.Fields {
			if nd.Fields.ForName(f.Name) == nil {
				removed = append(removed, fmt.Sprintf("- %s.%s", name, f.Name))
			}
		}
	}
	section("New scalar fields. Agents can read these in an allowed repo, so check none is a secret (add it to deniedFields in internal/policy/graphql.go if it is)", readable)
	section("New object fields. Check where each leads: agents read it in full unless it reaches a repo, an account, a project, or a type with a repository field, which get identity fields unless sameRepo lists the edge", edges)
	section("New query roots. Refused unless ClassifyGraphQL allows them", roots)
	section("New mutations. Refused unless the mutations table lists them", mutations)
	section("Removed types and fields. TestTablesMatchSchema fails if a policy table names one", removed)
	section("New types", types)
}

func section(title string, lines []string) {
	fmt.Printf("%s (%d)\n", title, len(lines))
	for _, l := range lines {
		fmt.Println("  " + l)
	}
	fmt.Println()
}

func sortedTypes(s *ast.Schema) []string {
	var names []string
	for name, d := range s.Types {
		if d.BuiltIn || strings.HasPrefix(name, "__") {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
