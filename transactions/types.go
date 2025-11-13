package transactions

import "strings"

type Label = string

type Transaction interface {
	Name() string
	Label() Label

	SetPrepareBlock(prepareBlock string) *SimpleTransaction
	SetExecuteBlock(executeBlock string) *SimpleTransaction
	SetFieldDeclarations(fieldDeclarations string) *SimpleTransaction

	GetPrepareBlock() string
	GetExecuteBlock() string
	GetFieldDeclarations() string
}

type Registry interface {
	Get(label Label) (Transaction, error)
	AllLabels() []Label
}

func TrimAndReplaceIndentation(s string, indentation int) string {
	// convert all tabs to spaces
	s = strings.ReplaceAll(s, "\t", "    ")

	// split into lines
	lines := strings.Split(s, "\n")
	// remove leading and trailing lines with only whitespace
	for len(lines) > 0 && len(strings.TrimSpace(lines[0])) == 0 {
		lines = lines[1:]
	}
	for len(lines) > 0 && len(strings.TrimSpace(lines[len(lines)-1])) == 0 {
		lines = lines[:len(lines)-1]
	}

	// get minimum spaces in all non-empty lines
	minSpaces := -1
	for _, line := range lines {
		spaces := 0
		for _, c := range line {
			if c == ' ' {
				spaces++
			} else {
				break
			}
		}
		if minSpaces == -1 || spaces < minSpaces {
			minSpaces = spaces
		}

	}

	// replace minSpaces from all non-empty lines with indentation spaces
	indentationStr := strings.Repeat(" ", indentation)
	for i, line := range lines {
		if len(line) > 0 {
			lines[i] = indentationStr + line[minSpaces:]
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
