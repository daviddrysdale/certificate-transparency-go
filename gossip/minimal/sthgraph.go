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
	"bytes"
	"fmt"
	"sort"
	"sync"

	ct "github.com/google/certificate-transparency-go"
)

// STHGraph holds a graph of known tree heads for a Log, where directed edges
// of the graph represent valid consistency proofs.  Safe for concurrent use.
type STHGraph struct {
	mu            sync.RWMutex
	nodesBySize   map[uint64]*ct.SignedTreeHead
	forwardEdges  map[uint64]map[uint64]bool
	backwardEdges map[uint64]map[uint64]bool
}

// NewSTHGraph builds an empty STHGraph object.
func NewSTHGraph() *STHGraph {
	return &STHGraph{
		nodesBySize:   make(map[uint64]*ct.SignedTreeHead),
		forwardEdges:  make(map[uint64]map[uint64]bool),
		backwardEdges: make(map[uint64]map[uint64]bool),
	}
}

func (g *STHGraph) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var froms []uint64
	for z := range g.forwardEdges {
		froms = append(froms, z)
	}
	sort.Slice(froms, func(i, j int) bool { return froms[i] < froms[j] })

	var buf bytes.Buffer
	for _, from := range froms {
		var tos []uint64
		for z := range g.forwardEdges[from] {
			tos = append(tos, z)
		}
		sort.Slice(tos, func(i, j int) bool { return tos[i] < tos[j] })
		for _, to := range tos {
			buf.WriteString(fmt.Sprintf("%d->%d,", from, to))
		}
	}
	return buf.String()
}

// STHForSize returns the STH recorded for a particular size, or nil if
// the given size has not been observed.
func (g *STHGraph) STHForSize(sz uint64) *ct.SignedTreeHead {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodesBySize[sz]
}

// AddSTH adds an observed STH to the graph, where signature validation is
// assumed to have already been done.  If the graph already includes an
// STH at the same size, then:
//  - sth is silently dropped if its root hash matches the existing entry.
//  - an error is returned if the root hash differs.
func (g *STHGraph) AddSTH(sth *ct.SignedTreeHead) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.addSTH(sth)
}

// addSTH is the internal version that assumes mu is held.
func (g *STHGraph) addSTH(sth *ct.SignedTreeHead) error {
	existing := g.nodesBySize[sth.TreeSize]
	if existing != nil {
		if !bytes.Equal(existing.SHA256RootHash[:], sth.SHA256RootHash[:]) {
			return fmt.Errorf("clashing hashes for size=%d: adding %x @ t=%d, got %x @ t=%d",
				sth.TreeSize, existing.SHA256RootHash, existing.Timestamp, sth.SHA256RootHash, sth.Timestamp)
		}
		return nil
	}
	g.nodesBySize[sth.TreeSize] = sth
	return nil
}

// AddEdge adds an edge between STHs to the graph, where the caller has checked
// that there is a valid consistency proof between the STHs.  If the STHs involved
// are not included in the graph, they are added.
func (g *STHGraph) AddEdge(from, to *ct.SignedTreeHead) error {
	if from.TreeSize == to.TreeSize {
		return nil
	}
	if from.TreeSize > to.TreeSize {
		return fmt.Errorf("edge in wrong direction %d->%d", from.TreeSize, to.TreeSize)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.addSTH(from); err != nil {
		return err
	}
	if err := g.addSTH(to); err != nil {
		return err
	}
	if g.forwardEdges[from.TreeSize] == nil {
		g.forwardEdges[from.TreeSize] = make(map[uint64]bool)
	}
	g.forwardEdges[from.TreeSize][to.TreeSize] = true
	if g.backwardEdges[to.TreeSize] == nil {
		g.backwardEdges[to.TreeSize] = make(map[uint64]bool)
	}
	g.backwardEdges[to.TreeSize][from.TreeSize] = true

	return nil
}

// SmallestReachablePrecursor returns the STH with the smallest tree size that
// can be reached from the given STH via a chain of edges (i.e. consistency
// proofs).  If no edges are available, the input STH will be returned.
func (g *STHGraph) SmallestReachablePrecursor(to *ct.SignedTreeHead) *ct.SignedTreeHead {
	g.mu.RLock()
	defer g.mu.RUnlock()

	_, smallestSize := g.reachablePrecursors(to.TreeSize)
	return g.nodesBySize[smallestSize]
}

func (g *STHGraph) reachablePrecursors(toSize uint64) (map[uint64]bool, uint64) {
	// Depth-first search for backwards-connected nodes
	smallestSize := toSize
	s := []uint64{smallestSize} // stack
	seen := make(map[uint64]bool)
	for len(s) > 0 {
		v := s[len(s)-1] // pop
		s = s[:len(s)-1]
		if !seen[v] {
			seen[v] = true
			if v < smallestSize {
				smallestSize = v
			}
			for w := range g.backwardEdges[v] {
				s = append(s, w) // push
			}
		}
	}
	return seen, smallestSize
}

// UnreachablePrecursor returns a slice of earlier STHs which cannot reached the given
// STH via chain of edges (i.e. consistency proofs); result is ordered by increasing tree size.
func (g *STHGraph) UnreachablePrecursors(to *ct.SignedTreeHead) []*ct.SignedTreeHead {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Depth-first search for backwards-connected nodes
	s := []uint64{to.TreeSize} // stack
	seen := make(map[uint64]bool)
	for len(s) > 0 {
		v := s[len(s)-1] // pop
		s = s[:len(s)-1]
		if !seen[v] {
			seen[v] = true
			for w := range g.backwardEdges[v] {
				s = append(s, w) // push
			}
		}
	}

	var results []*ct.SignedTreeHead
	for size, sth := range g.nodesBySize {
		if !seen[size] && sth.TreeSize < to.TreeSize {
			results = append(results, sth)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].TreeSize < results[j].TreeSize })
	return results
}

// STHEdge describes an edge between tree sizes.
type STHEdge struct {
	from, to uint64
}

// ConnectingEdges returns a collection of edges for the STH graph that, if
// added to the graph, would result in all known precursors of the given
// STH being reachable.  Returns nil for an already-precursor-connected
// graph.
func (g *STHGraph) ConnectingEdges(to *ct.SignedTreeHead) []STHEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// First build an slice of all precursors (including start node) in descending order of size.
	var sizes []uint64
	for size := range g.nodesBySize {
		if size > to.TreeSize {
			continue
		}
		sizes = append(sizes, size)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] > sizes[j] })

	var extras []STHEdge
	var prevSmallest uint64
	for len(sizes) > 0 {
		// Pick the largest unexamined node.
		rhs := sizes[0]
		// Find all its precursors (including itself) and remove them.
		seen, smallest := g.reachablePrecursors(rhs)
		for size := range seen {
			// TODO(daviddrysdale): use an efficient data structure her
			for i, v := range sizes {
				if v == size {
					sizes = append(sizes[:i], sizes[i+1:]...)
					break
				}
			}
		}
		if rhs == to.TreeSize {
			// This chunk is already connected to the initial node, so
			// no edge needed.
			continue
		}
		// Connect this chunk to the previously visited chunk.
		if rhs < prevSmallest {
			// Try to arrange the graph in a line if possible
			extras = append(extras, STHEdge{from: rhs, to: prevSmallest})
		} else {
			// A pair of connected sections like:
			//      4---7----10
			//        5---8
			// can't be arranged in a line, so just link to the
			// start node (8->10 in the example).
			extras = append(extras, STHEdge{from: rhs, to: to.TreeSize})
		}
		prevSmallest = smallest
	}
	return extras
}
