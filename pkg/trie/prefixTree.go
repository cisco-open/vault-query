// Copyright 2023 Cisco Systems, Inc. and its affiliates
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
//
// SPDX-License-Identifier: Apache-2.0

package trie

import (
	"fmt"
	"strings"
)

const Delim = "/"

type Tree struct {
	Root *Node `json:"root"`
}

type Node struct {
	Prefix []string         `json:"prefix"`
	Data   interface{}      `json:"data"`
	Edges  map[string]*Node `json:"edges"`
}

func NewTree() Tree {
	return Tree{Root: &Node{
		Edges: map[string]*Node{},
	}}
}

func (t *Tree) Lookup(prefix string) *Node {
	elems := strings.Split(prefix, Delim)
	return t.Root.lookup(elems)
}

func (n *Node) lookup(searchPrefix []string) *Node {
	// Scenarios are very similar to insertions
	for i, elem := range n.Prefix {
		// searchPrefix is substring of the node
		if i >= len(searchPrefix) {
			return n
		}
		// searchPrefix is a partial match of this node
		if elem != searchPrefix[i] {
			return n
		}
	}
	if len(n.Prefix) == len(searchPrefix) { // searchPrefix matches this node perfectly
		return n
	} else { // the node is a substring of the searchPrefix
		suffix := searchPrefix[len(n.Prefix):]
		edge, ok := n.Edges[suffix[0]]
		if !ok {
			return n
		} else {
			return edge.lookup(suffix)
		}
	}
}

func (t *Tree) Viz(skipPrefix string, renderLeaf func(string) string, renderPrefix func(string) string) {
	if skipPrefix == "" {
		t.Root.viz("", renderLeaf, renderPrefix)
	} else {
		node := t.Lookup(skipPrefix)
		node.viz("", renderLeaf, renderPrefix)
	}

}

func (n *Node) viz(indent string, renderLeaf func(string) string, renderPrefix func(string) string) {
	leafDataStr := ""
	if n.Data != nil {
		leafDataStr = renderLeaf(fmt.Sprintf("%v", n.Data))
	}

	if len(n.Edges) == 0 { // leaf
		prefixStr := strings.Join(n.Prefix[:], Delim)
		fmt.Printf("%s├─%s %s\n", indent, renderPrefix(prefixStr), leafDataStr)
	} else {
		prefixStr := strings.Join(n.Prefix[:], Delim) + Delim
		fmt.Printf("%s├─%s %s\n", indent, renderPrefix(prefixStr), leafDataStr)
	}
	for _, e := range n.Edges {
		e.viz(fmt.Sprintf("%s|    ", indent), renderLeaf, renderPrefix)
	}
}

func (t *Tree) Insert(prefix string, data interface{}, dataUpdateFunc *func(old interface{}, new interface{}) interface{}) {
	elems := strings.Split(strings.TrimSuffix(prefix, "/"), Delim) // split on `/`, remove any trailing /
	if len(t.Root.Prefix) == 0 {                                   // tree is empty
		t.Root.Data = data
		t.Root.Prefix = elems
	}
	t.Root.insert(elems, data, dataUpdateFunc)
}

func (n *Node) insert(input []string, inputData interface{}, dataUpdateFunc *func(old interface{}, new interface{}) interface{}) {
	// Find common elements between this node and input, and split accordingly
	// There are 4 scenarios:
	//
	// Scenario1: The input is same as the node elements e.g [input: ABC, node: ABC]
	//    - Update data
	//
	// Scenario2: Input is a substring of the node (len(node) > len(input)) e.g [input: ABC, node: ABCD]
	//  - Split the node where the difference is
	//  - Keep the common prefix in this node
	//  - Add another edge with the suffix
	//  - The Edges from this node transfer into the new node
	//
	// Scenario3: Node is a substring of the input (len(node) < len(input)) e.g [input: ABCD, node: ABC]
	//  - Search the Edges for a match and recursively insert
	//  - If no edge is found, add as a new edge
	//
	// Scenario 4: Some of the input is common, rest is different e.g. [input: ABC, node: ACD]
	//   - Split the node where the difference is
	//   - Keep the common prefix in this node
	//   - Add the two different suffixes as Edges of this node
	//   - The Edges from this node transfer into one of the new nodes

	//log.Printf("inserting input: %v, node: %v", input, n.Prefix)

	if sliceEqual(n.Prefix, input) { // Scenario 1
		//log.Println("SC1")
		if dataUpdateFunc != nil {
			n.Data = (*dataUpdateFunc)(n.Data, inputData) // Update the data using the user provided function
		} else {
			n.Data = inputData // else overwrite
		}
		return
	}

	// find where they differ
	indexDiff := 0
	for nodeItemIdx, elem := range n.Prefix {
		if nodeItemIdx >= len(input) {
			indexDiff = nodeItemIdx
			break
		}
		if elem != input[nodeItemIdx] {
			indexDiff = nodeItemIdx
			break
		}
	}

	if sliceHasPrefix(n.Prefix, input) { // Scenario 2
		//log.Println("SC2")
		childNodeElems := n.Prefix[indexDiff:]
		childNodeData := n.Data
		childEdgeNodes := n.Edges
		n.Prefix = input
		n.Data = inputData
		n.Edges = map[string]*Node{}
		n.Edges[childNodeElems[0]] = &Node{
			Prefix: childNodeElems,
			Data:   childNodeData,
			Edges:  childEdgeNodes,
		}
	} else if sliceHasPrefix(input, n.Prefix) { // Scenario 3
		//log.Println("SC3")
		// trim the prefix
		suffix := input[len(n.Prefix):]
		edgeNode, ok := n.Edges[suffix[0]]
		if !ok { // no edge found
			//log.Println("no existing edge found")
			n.Edges[suffix[0]] = &Node{
				Prefix: suffix,
				Data:   inputData,
				Edges:  map[string]*Node{},
			}
		} else {
			edgeNode.insert(suffix, inputData, dataUpdateFunc)
		}
	} else { // Scenario 4
		//log.Println("SC4")
		childNode1Elems := n.Prefix[indexDiff:]
		childNode1Data := n.Data
		childNode1Edges := n.Edges
		childNode2Elems := input[indexDiff:]
		childNode2Data := inputData
		childNode2Edges := map[string]*Node{}
		n.Prefix = n.Prefix[:indexDiff]
		n.Data = nil
		n.Edges = map[string]*Node{}
		n.Edges[childNode1Elems[0]] = &Node{
			Prefix: childNode1Elems,
			Data:   childNode1Data,
			Edges:  childNode1Edges,
		}
		n.Edges[childNode2Elems[0]] = &Node{
			Prefix: childNode2Elems,
			Data:   childNode2Data,
			Edges:  childNode2Edges,
		}
	}
}

func sliceEqual(s []string, prefix []string) bool {
	if len(s) != len(prefix) {
		return false
	}
	for i, c := range s {
		if c != prefix[i] {
			return false
		}
	}
	return true
}

func sliceHasPrefix(s []string, prefix []string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i, c := range s[0:len(prefix)] {
		if c != prefix[i] {
			return false
		}
	}
	return true
}

//func main() {
//	t := NewTree()
//	t.Insert("a/prod", map[string]bool{"get": true}, nil)
//	t.Insert("a/prod/a", map[string]bool{"get": true}, nil)
//	t.Insert("a/int", map[string]bool{"get": true}, nil)
//	t.Insert("a/int/b/c", map[string]bool{"get": true}, nil)
//	t.Insert("a/int/b/e/f", map[string]bool{"list": true}, nil)
//	t.Insert("b/prod/qwe", map[string]bool{"get": true}, nil)
//	t.Insert("b/prod/q", map[string]bool{"put": true}, nil)
//	t.Insert("b/prod/qwe/a", map[string]bool{"get": true}, nil)
//	//t.Viz("")
//	//t.Viz("b/prod")
//	b, err := json.Marshal(t)
//	if err != nil {
//		panic(err)
//	} else {
//		fmt.Println(string(b))
//	}
//
//	t2 := NewTree()
//	json.Unmarshal(b, &t2)
//	t2.Viz("")
//}
