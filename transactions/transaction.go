package transactions

import (
	"fmt"
)

type SimpleTransaction struct {
	name  string
	label Label

	prepareBlock      string
	executeBlock      string
	fieldDeclarations string
}

var _ Transaction = (*SimpleTransaction)(nil)

func NewSimpleTransaction(
	name string,
	label Label,
) *SimpleTransaction {
	return &SimpleTransaction{
		name:  name,
		label: label,
	}
}

func (s *SimpleTransaction) Name() string {
	return s.name
}

func (s *SimpleTransaction) Label() Label {
	return s.label
}

func (s *SimpleTransaction) SetPrepareBlock(
	prepareBlock string,
) *SimpleTransaction {
	s.prepareBlock = prepareBlock
	return s
}

func (s *SimpleTransaction) SetExecuteBlock(
	executeBlock string,
) *SimpleTransaction {
	s.executeBlock = executeBlock
	return s
}

func (s *SimpleTransaction) SetFieldDeclarations(
	fieldDeclarations string,
) *SimpleTransaction {
	s.fieldDeclarations = fieldDeclarations
	return s
}

func (s *SimpleTransaction) GetPrepareBlock() string {
	return s.prepareBlock
}

func (s *SimpleTransaction) GetExecuteBlock() string {
	return s.executeBlock
}

func (s *SimpleTransaction) GetFieldDeclarations() string {
	return s.fieldDeclarations
}

func LoopTemplate(
	n uint64,
	body string,
) string {
	return fmt.Sprintf(`
				var i = 0
				while i < %d {
					i = i + 1
					%s
				}`, n, body)
}
