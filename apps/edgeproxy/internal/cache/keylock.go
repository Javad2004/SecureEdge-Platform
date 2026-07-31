package cache

import "sync"

type keyLock struct {
	mu   sync.Mutex
	refs int
}

// KeyLocker serializes cache fills for the same key to prevent a cache stampede.
type KeyLocker struct {
	mu    sync.Mutex
	locks map[string]*keyLock
}

func NewKeyLocker() *KeyLocker {
	return &KeyLocker{locks: make(map[string]*keyLock)}
}

func (k *KeyLocker) Lock(key string) func() {
	k.mu.Lock()
	lk := k.locks[key]
	if lk == nil {
		lk = &keyLock{}
		k.locks[key] = lk
	}
	lk.refs++
	k.mu.Unlock()

	lk.mu.Lock()
	return func() {
		lk.mu.Unlock()
		k.mu.Lock()
		lk.refs--
		if lk.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
