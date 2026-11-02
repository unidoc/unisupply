package facts

import (
	"context"
	"slices"
	"sync"
)

// Memory is a Store held in the process. It is for tests, for a long-lived caller that wants facts shared between the scans
// it runs itself, and as the reference for what an implementation must do: it stores and returns copies, so a caller that
// changes a fact it read does not change the store.
type Memory struct {
	mu         sync.RWMutex
	modules    map[[2]string]Module
	advisories map[string]Advisory
	fixes      map[[2]string]Fix
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{modules: map[[2]string]Module{}, advisories: map[string]Advisory{}, fixes: map[[2]string]Fix{}}
}

var _ Store = (*Memory)(nil)

func (m *Memory) GetModule(_ context.Context, path, version string) (*Module, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.modules[[2]string{path, version}]
	if !ok {
		return nil, false, nil
	}
	return &v, true, nil
}

func (m *Memory) PutModule(_ context.Context, v *Module) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modules[[2]string{v.Path, v.Version}] = *v
	return nil
}

func (m *Memory) GetAdvisory(_ context.Context, id string) (*Advisory, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.advisories[id]
	if !ok {
		return nil, false, nil
	}
	v.Aliases = slices.Clone(v.Aliases)
	return &v, true, nil
}

func (m *Memory) PutAdvisory(_ context.Context, v *Advisory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *v
	c.Aliases = slices.Clone(v.Aliases)
	m.advisories[v.ID] = c
	return nil
}

func (m *Memory) GetFix(_ context.Context, module, version string) (*Fix, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.fixes[[2]string{module, version}]
	if !ok {
		return nil, false, nil
	}
	return &v, true, nil
}

func (m *Memory) PutFix(_ context.Context, v *Fix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fixes[[2]string{v.Module, v.Version}] = *v
	return nil
}
