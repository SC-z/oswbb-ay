package app

import (
	"fmt"

	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/modules"
)

type Registry struct {
	byName     map[modules.ModuleName]ModuleDescriptor
	byFileType map[core.FileType]modules.ModuleName
	order      []modules.ModuleName
}

func NewRegistry() *Registry {
	return &Registry{
		byName:     map[modules.ModuleName]ModuleDescriptor{},
		byFileType: map[core.FileType]modules.ModuleName{},
	}
}

func (r *Registry) Register(d ModuleDescriptor) error {
	if d.Name == "" {
		return fmt.Errorf("module name is required")
	}
	if d.Runner == nil {
		return fmt.Errorf("module %s runner is required", d.Name)
	}
	if _, exists := r.byName[d.Name]; exists {
		return fmt.Errorf("module %s already registered", d.Name)
	}
	for _, fileType := range d.FileTypes {
		if owner, exists := r.byFileType[fileType]; exists {
			return fmt.Errorf("file type %s already registered by %s", fileType, owner)
		}
	}
	d.FileTypes = append([]core.FileType(nil), d.FileTypes...)
	r.byName[d.Name] = d
	for _, fileType := range d.FileTypes {
		r.byFileType[fileType] = d.Name
	}
	r.order = append(r.order, d.Name)
	return nil
}

func (r *Registry) Get(name modules.ModuleName) (ModuleDescriptor, error) {
	d, ok := r.byName[name]
	if !ok {
		return ModuleDescriptor{}, fmt.Errorf("unknown module: %s", name)
	}
	return cloneDescriptor(d), nil
}

func (r *Registry) Resolve(fileType core.FileType) (ModuleDescriptor, error) {
	name, ok := r.byFileType[fileType]
	if !ok {
		return ModuleDescriptor{}, fmt.Errorf("unknown file type: %s", fileType)
	}
	return r.Get(name)
}

func (r *Registry) List() []ModuleDescriptor {
	result := make([]ModuleDescriptor, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, cloneDescriptor(r.byName[name]))
	}
	return result
}

func cloneDescriptor(d ModuleDescriptor) ModuleDescriptor {
	d.FileTypes = append([]core.FileType(nil), d.FileTypes...)
	return d
}
