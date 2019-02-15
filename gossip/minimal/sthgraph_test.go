// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package minimal

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
)

func testSTHFor(sz, ts uint64, hash string) *ct.SignedTreeHead {
	return &ct.SignedTreeHead{TreeSize: sz, Timestamp: ts, SHA256RootHash: sha256.Sum256([]byte(hash))}
}

func testSTH(sz uint64) *ct.SignedTreeHead {
	return testSTHFor(sz, 1000*sz, fmt.Sprintf("%d", sz))
}

func TestSTHGraph(t *testing.T) {
	var sth [8]*ct.SignedTreeHead
	for i := range sth {
		sth[i] = testSTH(uint64(i))
	}
	sth0_2 := testSTHFor(0, 10, "0")
	sth0_2Alt := testSTHFor(0, 20, "0_alt")
	sth1Alt := testSTHFor(1, 1010, "1_alt")

	// Note: tests are cumulative
	tests := []struct {
		nodes   [2]*ct.SignedTreeHead // nodes[1]==nil for AddSTH
		wantErr bool
		to      *ct.SignedTreeHead
		wantU   []*ct.SignedTreeHead
		wantR   *ct.SignedTreeHead
		wantE   []STHEdge
	}{
		{nodes: [2]*ct.SignedTreeHead{sth[0], nil}},                      // graph={0}
		{nodes: [2]*ct.SignedTreeHead{sth[0], nil}},                      // duplicate node OK
		{nodes: [2]*ct.SignedTreeHead{sth0_2, nil}},                      // same size, different timestamp, same hash OK
		{nodes: [2]*ct.SignedTreeHead{sth[0], sth0_2}},                   // self-edge ignored
		{nodes: [2]*ct.SignedTreeHead{sth0_2Alt, nil}, wantErr: true},    // clashing root hash
		{nodes: [2]*ct.SignedTreeHead{sth0_2, sth[1]}},                   // graph={0->1}
		{nodes: [2]*ct.SignedTreeHead{sth0_2, sth[1]}},                   // duplicate edge OK
		{nodes: [2]*ct.SignedTreeHead{sth0_2Alt, sth[1]}, wantErr: true}, // clashing root hash in from
		{nodes: [2]*ct.SignedTreeHead{sth[0], sth1Alt}, wantErr: true},   // clashing root hash in to
		{nodes: [2]*ct.SignedTreeHead{sth[2], sth[1]}, wantErr: true},    // backwards edge
		{
			// all earlier nodes reachable from 1
			to:    sth[1],
			wantU: nil,
			wantR: sth[0],
		},
		{nodes: [2]*ct.SignedTreeHead{sth[2], nil}}, // graph={0->1, 2}
		{
			// nothing reachable back from 2
			to:    sth[2],
			wantU: []*ct.SignedTreeHead{sth[0], sth[1]},
			wantR: sth[2],
			wantE: []STHEdge{{from: 1, to: 2}},
		},
		{nodes: [2]*ct.SignedTreeHead{sth[1], sth[2]}}, // graph={0->1->2}
		{nodes: [2]*ct.SignedTreeHead{sth[2], sth[4]}}, // graph={0->1->2->4}
		{nodes: [2]*ct.SignedTreeHead{sth[4], sth[6]}}, // graph={0->1->2->4->6}
		{nodes: [2]*ct.SignedTreeHead{sth[1], sth[3]}}, // graph={0->1->2->4->6,1->3}
		{nodes: [2]*ct.SignedTreeHead{sth[3], sth[5]}}, // graph={0->1->2->4->6,1->3->5}
		{
			// can't reach 2, 4 from 5, can reach 0
			to:    sth[5],
			wantU: []*ct.SignedTreeHead{sth[2], sth[4]},
			wantR: sth[0],
			wantE: []STHEdge{{from: 4, to: 5}},
		},
		{
			// can't reach 3, 5 from 6, can reach 0
			to:    sth[6],
			wantU: []*ct.SignedTreeHead{sth[3], sth[5]},
			wantR: sth[0],
			wantE: []STHEdge{{from: 5, to: 6}},
		},
		{
			// can't reach 2 from 3, can reach 0
			to:    sth[3],
			wantU: []*ct.SignedTreeHead{sth[2]},
			wantR: sth[0],
			wantE: []STHEdge{{from: 2, to: 3}},
		},
		{nodes: [2]*ct.SignedTreeHead{sth[5], sth[6]}}, // graph={0->1->2->4->6,1->3->5->6}
		{
			// all joined up now
			to:    sth[6],
			wantU: nil,
			wantR: sth[0],
			wantE: nil,
		},
		{nodes: [2]*ct.SignedTreeHead{sth[7], nil}}, // graph={0->1->2->4->6,1->3->5->6, 7}
		{
			to:    sth[7],
			wantU: []*ct.SignedTreeHead{sth[0], sth[1], sth[2], sth[3], sth[4], sth[5], sth[6]},
			wantR: sth[7],
			wantE: []STHEdge{{from: 6, to: 7}},
		},
	}
	graph := NewSTHGraph()
	for _, test := range tests {
		if test.nodes[0] != nil {
			var err error
			if test.nodes[1] == nil {
				err = graph.AddSTH(test.nodes[0])
			} else {
				err = graph.AddEdge(test.nodes[0], test.nodes[1])
			}
			if err != nil {
				if !test.wantErr {
					t.Fatalf("Add(%v, %v)=%v, want nil", test.nodes[0], test.nodes[1], err)
				}
				continue
			}

			// Check that the node got added (but it may have a different timestamp).
			got, want := graph.STHForSize(test.nodes[0].TreeSize), test.nodes[0]
			if got.TreeSize != want.TreeSize || got.SHA256RootHash != want.SHA256RootHash {
				t.Errorf("STHForSize(%d)=%v, want %v", test.nodes[0].TreeSize, got, want)
			}
		}
		if test.to == nil {
			continue
		}
		gotU := graph.UnreachablePrecursors(test.to)
		if !reflect.DeepEqual(gotU, test.wantU) {
			t.Errorf("UnreachablePrecursors(%d, {%s})=%v, want %v", test.to.TreeSize, graph, gotU, test.wantU)
		}
		gotR := graph.SmallestReachablePrecursor(test.to)
		if !reflect.DeepEqual(gotR, test.wantR) {
			t.Errorf("SmallestReachablePrecursor(%d, {%s})=%v, want %v", test.to.TreeSize, graph, gotR, test.wantR)
		}
		gotE := graph.ConnectingEdges(test.to)
		if !reflect.DeepEqual(gotE, test.wantE) {
			t.Errorf("ConnectingEdges(%d, {%s})=%v, want %v", test.to.TreeSize, graph, gotE, test.wantE)
		}
	}
	if got, want := graph.String(), "0->1,1->2,1->3,2->4,3->5,4->6,5->6,"; got != want {
		t.Errorf("graph=%s, want %s", got, want)
	}
}

func TestRandomSTHGraph(t *testing.T) {
	maxSize := 60
	graphCount := 100
	opCount := 100
	for i := 0; i < graphCount; i++ {
		t.Run(fmt.Sprintf("test-%02d", i), func(t *testing.T) {
			// Build a random graph
			graph := NewSTHGraph()
			largest := uint64(0)
			for j := 0; j < opCount; j++ {
				x := uint64(rand.Intn(maxSize))
				y := uint64(rand.Intn(3 * maxSize / 2))
				var err error
				if y > uint64(maxSize) {
					err = graph.AddSTH(testSTH(x))
					if y > largest {
						largest = y
					}
				} else if x < y {
					err = graph.AddEdge(testSTH(x), testSTH(y))
					if y > largest {
						largest = y
					}
				} else if x > y {
					err = graph.AddEdge(testSTH(y), testSTH(x))
					if x > largest {
						largest = x
					}
				}
				if err != nil {
					t.Fatalf("graph.Add() for %d,%d failed: %v", x, y, err)
				}
			}

			// Connect up the graph.
			edges := graph.ConnectingEdges(testSTH(largest))
			for _, edge := range edges {
				if err := graph.AddEdge(testSTH(edge.from), testSTH(edge.to)); err != nil {
					t.Fatalf("graph.AddEdge(%d, %d) failed: %v", edge.from, edge.to, err)
				}
			}

			// Everything should now be reachable.
			if got := graph.UnreachablePrecursors(testSTH(largest)); got != nil {
				t.Errorf("graph still has unreachable precursors: %v", got)
			}
		})
	}
}
