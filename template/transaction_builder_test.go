package template_test

import (
	"testing"

	"github.com/onflow/flow-standard-transactions/registry"
	"github.com/onflow/flow-standard-transactions/template"
	"github.com/rs/zerolog"

	"github.com/stretchr/testify/require"
)

func Test_TransactionNew(t *testing.T) {
	t.Parallel()

	reg := registry.NewRegistry()
	err := reg.Register(template.NewSimpleTemplate(
		"T1",
		"T1",
		1,
	))
	require.NoError(t, err)

	body := template.NewTransactionBuilder(zerolog.Nop(), reg).BuildTransaction()
	require.NotEmpty(t, body)
}

func Test_TransactionBuilder(t *testing.T) {
	t.Parallel()

	reg := registry.SimpleRegistry.Clone()

	require.NotEmpty(t, reg.AllLabels())

}
