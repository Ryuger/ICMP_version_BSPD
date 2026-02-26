//go:build !postgres && !sqlite

package store

func NewStore() (Store, error) {
	return NewMemoryStore(), nil
}
