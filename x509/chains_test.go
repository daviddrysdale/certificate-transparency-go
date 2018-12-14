// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

var (
	notBefore = time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2100, 1, 1, 12, 0, 0, 0, time.UTC)
)

// Simple (and inefficient) graph structure.
type graphEdge struct {
	left, right string
}

type graph struct {
	edges []*graphEdge
	nodes map[string]bool
}

// newGraph builds a graph struct from a collection of edges in the
// form "name->name2".
func newGraph(t *testing.T, edges []string) *graph {
	t.Helper()
	g := graph{nodes: make(map[string]bool)}
	for _, e := range edges {
		nodes := strings.Split(e, "->")
		if len(nodes) != 2 {
			t.Fatalf("Edge %s doesn't have two nodes", e)
		}
		g.addEdge(nodes[0], nodes[1])
	}
	return &g
}

func (g *graph) addEdge(l, r string) {
	g.edges = append(g.edges, &graphEdge{left: l, right: r})
	g.nodes[l] = true
	g.nodes[r] = true
}

func (g *graph) removeEdge(l, r string) {
	for i, e := range g.edges {
		if e.left == l && e.right == r {
			g.edges = append(g.edges[:i], g.edges[i+1:]...)
			// Note g.nodes is left untouched.
			return
		}
	}
}

func (g *graph) edgesFrom(l string) []string {
	var results []string
	for _, e := range g.edges {
		if e.left != l {
			continue
		}
		results = append(results, e.right)
	}
	return results
}

func (g *graph) edgesTo(r string) []string {
	var results []string
	for _, e := range g.edges {
		if e.right != r {
			continue
		}
		results = append(results, e.left)
	}
	return results
}

func (g *graph) nodesWithNoIncomingEdge() []string {
	var results []string
	for r, _ := range g.nodes {
		if len(g.edgesTo(r)) == 0 {
			results = append(results, r)
		}
	}
	return results
}

// Return a topologically sorted list of the nodes in the graph.
func (g *graph) sortedNodes(t *testing.T) []string {
	// Make a copy of the graph to allow modification.
	gcopy := &graph{
		edges: make([]*graphEdge, len(g.edges)),
		nodes: g.nodes,
	}
	copy(gcopy.edges, g.edges)

	// Kahn's algorithm to topologically sort the nodes.
	var sortedNodes []string
	noIncomingNodes := gcopy.nodesWithNoIncomingEdge()
	for len(noIncomingNodes) > 0 {
		node := noIncomingNodes[0]
		noIncomingNodes = noIncomingNodes[1:]
		sortedNodes = append(sortedNodes, node)
		for _, m := range gcopy.edgesFrom(node) {
			gcopy.removeEdge(node, m)
			if len(gcopy.edgesTo(m)) == 0 {
				noIncomingNodes = append(noIncomingNodes, m)
			}
		}
	}
	if len(gcopy.edges) > 0 {
		t.Fatal("graph has cycle")
	}
	return sortedNodes
}

type certGraph struct {
	privKey map[string]*ecdsa.PrivateKey // keyName (with number suffix dropped) => key
	cert    map[string]*x509.Certificate // name => cert
	opts    x509.VerifyOptions
}

// Build a graph of certificates from edges specified as "name->name".
// Conventions:
//   - Node names that are <name><number> indicate that all certs with
//     the same name should share a private key (so "CA1", "CA2" and "CA3"
//     will all use a private key identified by "CA").
//   - Names starting with a lowercase letter are non-CA leaf certs.
func newCertGraph(t *testing.T, edges []string) *certGraph {
	g := certGraph{
		privKey: make(map[string]*ecdsa.PrivateKey),
		cert:    make(map[string]*x509.Certificate),
		opts: x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
		},
	}

	// First build the private keys.
	graph := newGraph(t, edges)
	for node, _ := range graph.nodes {
		// Should be 0 or 1 incoming edges for each node.
		if signers := graph.edgesTo(node); len(signers) > 1 {
			t.Fatalf("Node %s signed by multiple signers %v", node, signers)
		}
		keyName := stripSuffix(node)
		if g.privKey[keyName] == nil {
			var err error
			g.privKey[keyName], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate private key for %s: %v", keyName, err)
			}
		}
	}

	// Now build certificates.  This relies on seeing certificates in a topologically sorted order,
	// so issuer certificates are available before things they sign.
	for _, name := range graph.sortedNodes(t) {
		keyName := stripSuffix(name)
		pubKey := g.privKey[keyName].Public()

		var issuerName string
		issuerKeyName := keyName
		if signers := graph.edgesTo(name); len(signers) > 0 { // Not self-signed
			issuerName = signers[0]
			issuerKeyName = stripSuffix(issuerName)
		}

		// Cert for (e.g.) node "A3" will have common name (and keyID) "A" and serial number 3.
		template := &x509.Certificate{
			Subject:            pkix.Name{CommonName: keyName},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			SerialNumber:       big.NewInt(suffixNum(name)),
			PublicKey:          pubKey,
			SubjectKeyId:       []byte(keyName),
			AuthorityKeyId:     []byte(issuerKeyName),
			NotBefore:          notBefore,
			NotAfter:           notAfter,
		}
		// Names starting with upper case are assumed to be CA certs.
		isCA := unicode.IsUpper(rune(name[0]))
		if isCA {
			template.BasicConstraintsValid = true
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		}
		issuer := g.cert[issuerName] // relies on topological sort
		if len(issuerName) == 0 {    // self-signed
			issuer = template
		}
		data, err := x509.CreateCertificate(rand.Reader, template, issuer, pubKey, g.privKey[issuerKeyName])
		if err != nil {
			t.Fatalf("Failed to CreateCertificate for %s: %v", name, err)
		}
		g.cert[name], err = x509.ParseCertificate(data)
		if err != nil {
			t.Fatalf("Failed to ParseCertificate for %s: %v", name, err)
		}

		if issuer == template {
			g.opts.Roots.AddCert(g.cert[name])
		} else if isCA {
			g.opts.Intermediates.AddCert(g.cert[name])
		}
	}

	return &g
}

func stripSuffix(s string) string {
	return strings.TrimRight(s, "0123456789")
}

func suffixNum(s string) int64 {
	pos := strings.IndexAny(s, "0123456789")
	if pos == -1 {
		return 0
	}
	val, err := strconv.ParseInt(s[pos:], 10, 64)
	if err != nil {
		return 0
	}
	return val
}

func certName(c *x509.Certificate) string {
	suffix := ""
	if serial := c.SerialNumber.Int64(); serial > 0 {
		suffix = fmt.Sprintf("%d", serial)
	}
	return c.Subject.CommonName + suffix
}

func chainSummary(chain []*x509.Certificate) string {
	var buf bytes.Buffer
	for j, cert := range chain {
		if j > 0 {
			buf.WriteString(" ")
		}
		buf.WriteString(certName(cert))
	}
	return buf.String()
}

func chainsSummary(chains [][]*x509.Certificate) []string {
	results := make([]string, len(chains))
	for i, chain := range chains {
		results[i] = chainSummary(chain)
	}
	sort.Strings(results)
	return results
}

func TestChainGeneration(t *testing.T) {
	type nodeTest struct {
		name string
		want []string // keep sorted
	}
	tests := []struct {
		desc  string
		graph *certGraph
		nodes []nodeTest
	}{
		{
			//  R--B--A--l
			desc:  "linear",
			graph: newCertGraph(t, []string{"R->B", "B->A", "A->l"}),
			nodes: []nodeTest{
				{name: "B", want: []string{"B R"}},
				{name: "A", want: []string{"A B R"}},
				{name: "l", want: []string{"l A B R"}},
			},
		},
		{
			//    R
			//    |
			//    B1  B2   <-- same private key
			//        |
			//        A
			//        |
			//        l
			desc:  "cross-signed-root",
			graph: newCertGraph(t, []string{"R->B1", "B2->A", "A->l"}),
			nodes: []nodeTest{
				{name: "B1", want: []string{"B1 R"}},
				{name: "B2", want: []string{"B2"}},
				{name: "A", want: []string{"A B1 R", "A B2"}},
				{name: "l", want: []string{"l A B1 R", "l A B2"}},
			},
		},
		{
			//    R   S
			//    |   |
			//    I1  I2   <-- same private key
			//        |
			//        l
			desc:  "cross-signed-intermediate",
			graph: newCertGraph(t, []string{"R->I1", "S->I2", "I2->l"}),
			nodes: []nodeTest{
				{name: "R", want: []string{"R"}},
				{name: "S", want: []string{"S"}},
				{name: "I1", want: []string{"I1 R"}},
				{name: "I2", want: []string{"I2 S"}},
				{name: "l", want: []string{"l I1 R", "l I2 S"}},
			},
		},
		{
			//        R
			//       / \
			//      /   B
			//     /   / \
			//    A1  A2 A3   <-- same private key
			//    |
			//    l
			desc:  "three-subordinates",
			graph: newCertGraph(t, []string{"R->B", "R->A1", "B->A2", "B->A3", "A1->l"}),
			nodes: []nodeTest{
				{name: "B", want: []string{"B R"}},
				{name: "A1", want: []string{"A1 R"}},
				{name: "A2", want: []string{"A2 B R"}},
				{name: "A3", want: []string{"A3 B R"}},
				{name: "l", want: []string{"l A1 R", "l A2 B R", "l A3 B R"}},
			},
		},
		{
			//        R
			//       / \
			//      /   B
			//     /    |
			//    A1    A2   <-- same private key
			//    |
			//    l
			desc:  "two-subordinates-one-intermediate",
			graph: newCertGraph(t, []string{"R->B", "R->A1", "B->A2", "A1->l"}),
			nodes: []nodeTest{
				{name: "B", want: []string{"B R"}},
				{name: "A1", want: []string{"A1 R"}},
				{name: "A2", want: []string{"A2 B R"}},
				{name: "l", want: []string{"l A1 R", "l A2 B R"}},
			},
		},
		{
			//        R___
			//       / \  \
			//      /  B1  B2   <-- same private key
			//     /   |   |
			//    A1   A2  A3   <-- same private key
			//         |
			//         l
			desc:  "three-subordinates-two-intermediates",
			graph: newCertGraph(t, []string{"R->B1", "R->B2", "R->A1", "B1->A2", "B2->A3", "A2->l"}),
			nodes: []nodeTest{
				{name: "B1", want: []string{"B1 R"}},
				{name: "B2", want: []string{"B2 R"}},
				{name: "A1", want: []string{"A1 R"}},
				{name: "A2", want: []string{"A2 B1 R", "A2 B2 R"}},
				{name: "A3", want: []string{"A3 B1 R", "A3 B2 R"}},
				{name: "l", want: []string{"l A1 R", "l A2 B1 R", "l A2 B2 R", "l A3 B1 R", "l A3 B2 R"}},
			},
		},
		{
			//   R   S
			//   |   |
			//   B1  B2   <-- same private key
			//   |   |
			//   A1  A2   <-- same private key
			//   |   |
			//   l   m
			desc:  "two-subordinates-two-intermediates-two-roots",
			graph: newCertGraph(t, []string{"R->B1", "B1->A1", "S->B2", "B2->A2", "A1->l", "A2->m"}),
			nodes: []nodeTest{
				{name: "B1", want: []string{"B1 R"}},
				{name: "B2", want: []string{"B2 S"}},
				{name: "A1", want: []string{"A1 B1 R", "A1 B2 S"}},
				{name: "A2", want: []string{"A2 B1 R", "A2 B2 S"}},
				{name: "l", want: []string{"l A1 B1 R", "l A1 B2 S", "l A2 B1 R", "l A2 B2 S"}},
				{name: "m", want: []string{"m A1 B1 R", "m A1 B2 S", "m A2 B1 R", "m A2 B2 S"}},
			},
		},
		{
			//     R
			//     |
			//     B
			//   /  \
			//   A1  A2   <-- same private key
			//   |   |
			//   l   m
			desc:  "two-subordinates",
			graph: newCertGraph(t, []string{"R->B", "B->A1", "B->A2", "A1->l", "A2->m"}),
			nodes: []nodeTest{
				{name: "B", want: []string{"B R"}},
				{name: "A1", want: []string{"A1 B R"}},
				{name: "A2", want: []string{"A2 B R"}},
				{name: "l", want: []string{"l A1 B R", "l A2 B R"}},
				{name: "m", want: []string{"m A1 B R", "m A2 B R"}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			for _, n := range test.nodes {
				if _, ok := test.graph.cert[n.name]; !ok {
					t.Fatalf("test node %s not in cert graph!", n.name)
				}
				chains, err := test.graph.cert[n.name].Verify(test.graph.opts)
				if err != nil {
					t.Fatalf("failed to verify: %v\n", err)
				}
				if got := chainsSummary(chains); !reflect.DeepEqual(got, n.want) {
					t.Errorf("Verify(%s)=%v, want %v", n.name, strings.Join(got, ", "), strings.Join(n.want, ", "))
				}
			}
		})
	}
}
