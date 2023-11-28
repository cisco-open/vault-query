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
	"github.com/charmbracelet/lipgloss"
)

// For error messages
var textErr = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#e03f3f"))

// For warning messages
var textWarn = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#e0cb3f"))

// For general logs
var textNote = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#e3e3e3"))

// For info messages (but with margin and bold for emphasis)
var textNoteEmphasis = textNote.Copy().
	Bold(true).
	MarginTop(1).
	MarginBottom(1)

// For info messages
var textInfo = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#00aaff"))

// For messages that are "positive"
var textSuccess = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#3bdb7b"))

// For messages that are "negative"
var textFailure = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#e03f3f"))

// For list items
var tListItem0 = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#ffbb00"))

// For showing map keys
var tMapKey = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#ffbb00"))

// For showing map keys (with underline)
var tMapKeyU = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#ffbb00")).
	Underline(true)

// For Map keys (indent x2)
var tMapKey2 = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#00aaff"))

// For showing index
var textIndex = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#ededed"))

var textLightGray = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#bababa"))

// When asking user for input
var textInput = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#edf3fa")).
	SetString("\n>>")

// For showing commands
var textCmd = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#FAFAFA")).
	Background(lipgloss.Color("#363535")).
	MarginTop(1).
	MarginBottom(1)

// For showing code
var policyCodeStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#FAFAFA")).
	Background(lipgloss.Color("#363636")).
	PaddingTop(1).
	PaddingLeft(4).
	Width(120).
	MarginLeft(4)

// For showing code snippets
var policyCodeStyleSmall = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#FAFAFA")).
	Background(lipgloss.Color("#363636")).
	PaddingLeft(4).
	MarginLeft(8).
	Width(120)

// For vault namespace
var textNamespace = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#7553fc")).
	Underline(true)
