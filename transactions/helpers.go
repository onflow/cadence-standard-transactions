package transactions

import (
	"strconv"
	"strings"
)

func stringOfLen(length uint64) string {
	someString := make([]byte, length)
	for i := 0; i < len(someString); i++ {
		someString[i] = 'x'
	}
	return string(someString)
}

func stringDictOfLen(dictLen uint64, stringLen uint64) string {
	builder := strings.Builder{}
	builder.WriteRune('{')
	for i := uint64(0); i < dictLen; i++ {
		if i > 0 {
			builder.WriteRune(',')
		}
		builder.WriteRune('"')
		someString := make([]byte, stringLen)
		for i := 0; i < len(someString); i++ {
			someString[i] = 'x'
		}
		builder.WriteString(string(someString))
		builder.WriteString(strconv.Itoa(int(i)))
		builder.WriteRune('"')
		builder.WriteRune(':')
		builder.WriteRune('"')
		builder.WriteString(string(someString))
		builder.WriteRune('"')
	}
	builder.WriteRune('}')
	return builder.String()
}

func simpleTransactionWithLoop(
	name string,
	label Label,
	initialLoopLength uint64,
	body string,
) *SimpleTransaction {
	return NewSimpleTransaction(
		name,
		label,
	).
		SetPrepareBlock(LoopTemplate(initialLoopLength, body))
}
