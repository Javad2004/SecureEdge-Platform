package admission

import "sync"

type Limiter struct {
	mu        sync.Mutex
	global    int
	perClient map[string]int
}

type Snapshot struct {
	GlobalActive   int            `json:"global_active"`
	ClientActive   map[string]int `json:"client_active,omitempty"`
	TrackedClients int            `json:"tracked_clients"`
}

func New() *Limiter { return &Limiter{perClient: map[string]int{}} }

// Acquire is deliberately non-blocking. Rejecting overload protects the WAF,
// EdgeProxy, and origin from request queues that would otherwise amplify load.
func (l *Limiter) Acquire(client string, globalLimit, clientLimit int) (func(), bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global >= globalLimit {
		return nil, false, "global_concurrency"
	}
	if l.perClient[client] >= clientLimit {
		return nil, false, "client_concurrency"
	}
	l.global++
	l.perClient[client]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.global--
			l.perClient[client]--
			if l.perClient[client] <= 0 {
				delete(l.perClient, client)
			}
		})
	}, true, ""
}

func (l *Limiter) Snapshot(includeClients bool) Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Snapshot{GlobalActive: l.global, TrackedClients: len(l.perClient)}
	if includeClients {
		s.ClientActive = make(map[string]int, len(l.perClient))
		for k, v := range l.perClient {
			s.ClientActive[k] = v
		}
	}
	return s
}
