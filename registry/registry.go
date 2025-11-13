package registry

import (
	"github.com/onflow/flow-standard-transactions/errors"
	"github.com/onflow/flow-standard-transactions/template"
)

type Registry struct {
	templates map[template.Label]template.Template
}

var _ template.Registry = &Registry{}

func NewRegistry() Registry {
	return Registry{
		templates: make(map[template.Label]template.Template),
	}
}

func (r Registry) Clone() Registry {
	templ := make(map[template.Label]template.Template)
	for label, template := range r.templates {
		templ[label] = template
	}
	return Registry{
		templates: templ,
	}
}

func (r Registry) Register(template template.Template) error {
	if _, ok := r.templates[template.Label()]; ok {
		return errors.NewTemplateAlreadyRegistered(template.Label())
	}

	r.templates[template.Label()] = template
	return nil
}

func (r Registry) RegisterAll(template []template.Template) error {
	for _, templ := range template {
		if err := r.Register(templ); err != nil {
			return err
		}
	}
	return nil
}

func (r Registry) Unregister(labels ...template.Label) Registry {
	for _, label := range labels {
		delete(r.templates, label)
	}
	return r
}

func (r Registry) Get(label template.Label) (template.Template, error) {
	templ, ok := r.templates[label]
	if !ok {
		return nil, errors.NewTemplateNotFound(label)
	}

	return templ, nil
}

func (r Registry) AllLabels() []template.Label {
	labels := make([]template.Label, 0, len(r.templates))
	for label := range r.templates {
		labels = append(labels, label)
	}
	return labels
}

var SimpleRegistry Registry
var ContractRegistry Registry
var ScheduledRegistry Registry

func init() {
	SimpleRegistry = NewRegistry()
	ContractRegistry = NewRegistry()
	ScheduledRegistry = NewRegistry()

	err := SimpleRegistry.RegisterAll(SimpleTemplates)
	if err != nil {
		panic(err)
	}
	err = ContractRegistry.RegisterAll(ContractTemplates)
	if err != nil {
		panic(err)
	}

	err = ScheduledRegistry.RegisterAll(ScheduledTransactions)
	if err != nil {
		panic(err)
	}
}

type InitialParametersData struct {
	Templates map[template.Label]TemplateInitialParameters `json:"templates"`
}

type TemplateInitialParameters struct {
	InitialParameters []uint64 `json:"parameters"`
}
