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

package ansi

import (
	"fmt"
	"strconv"
)

func Printfc(color FgColor, format string, a ...interface{}) (n int, err error) {
	fmt.Printf(string(color))
	return fmt.Printf(format+"\033[0m", a...)
}

func Printfcb(bgColor BgColor, textColor FgColor, format string, a ...interface{}) (n int, err error) {
	fmt.Printf(string(bgColor))
	fmt.Printf(string(textColor))
	return fmt.Printf(format, a)
}

func SetCursorPos(x int, y int) {
	cursorPos := "\033[" + strconv.Itoa(x) + ";" + strconv.Itoa(y) + "H"
	fmt.Printf(cursorPos)
}

func ClearScreen() {
	fmt.Printf("\033[2J")
}

func ClearLine() {
	clearLine := "\033[K"
	fmt.Printf(clearLine)
}

func ClearFormatting() {
	fmt.Printf("\033[0m")

}

type FgColor string

const (
	FgBlack         FgColor = "\033[30m"
	FgRed           FgColor = "\033[31m"
	FgGreen         FgColor = "\033[32m"
	FgYellow        FgColor = "\033[33m"
	FgBlue          FgColor = "\033[34m"
	FgMagenta       FgColor = "\033[35m"
	FgCyan          FgColor = "\033[36m"
	FgWhite         FgColor = "\033[37m"
	FgGray          FgColor = "\033[90m"
	FgBrightRed     FgColor = "\033[91m"
	FgBrightGreen   FgColor = "\033[92m"
	FgBrightYellow  FgColor = "\033[93m"
	FgBrightBlue    FgColor = "\033[94m"
	FgBrightMagenta FgColor = "\033[95m"
	FgBrightCyan    FgColor = "\033[96m"
	FgBrightWhite   FgColor = "\033[97m"
)

type BgColor string

const (
	BgBlack         BgColor = "\033[40m"
	BgRed           BgColor = "\033[41m"
	BgGreen         BgColor = "\033[42m"
	BgYellow        BgColor = "\033[43m"
	BgBlue          BgColor = "\033[44m"
	BgMagenta       BgColor = "\033[45m"
	BgCyan          BgColor = "\033[46m"
	BgWhite         BgColor = "\033[47m"
	BgGray          BgColor = "\033[100m"
	BgBrightRed     BgColor = "\033[101m"
	BgBrightGreen   BgColor = "\033[102m"
	BgBrightYellow  BgColor = "\033[103m"
	BgBrightBlue    BgColor = "\033[104m"
	BgBrightMagenta BgColor = "\033[105m"
	BgBrightCyan    BgColor = "\033[106m"
	BgBrightWhite   BgColor = "\033[107m"
)
