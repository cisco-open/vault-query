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

package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"strings"
)

type Policy struct {
	Name      string
	Namespace string
}

func (p Policy) Title() string       { return p.Name }
func (p Policy) Description() string { return p.Namespace }
func (p Policy) FilterValue() string { return p.Name }

type model struct {
	cursor int
	choice Policy
}

var _policySelectorChoices = []Policy{}
var _policySelectorTitle string

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			os.Exit(0)

		case "enter":
			// Send the choice on the channel and exit.
			m.choice = _policySelectorChoices[m.cursor]
			return m, tea.Quit

		case "down", "j":
			m.cursor++
			if m.cursor >= len(_policySelectorChoices) {
				m.cursor = 0
			}

		case "up", "k":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(_policySelectorChoices) - 1
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	s := strings.Builder{}
	s.WriteString(fmt.Sprintln(textInput.Render(_policySelectorTitle)))
	for i := 0; i < len(_policySelectorChoices); i++ {
		if m.cursor == i {
			s.WriteString(textIndex.MarginLeft(2).Render("[X] "))
		} else {
			s.WriteString(textIndex.MarginLeft(2).Render("[ ] "))
		}
		s.WriteString(fmt.Sprintf("%s %s",
			tListItem0.Render(_policySelectorChoices[i].Name),
			textNamespace.Render("["+_policySelectorChoices[i].Namespace+"]")))
		s.WriteString("\n")
	}

	return s.String()
}
