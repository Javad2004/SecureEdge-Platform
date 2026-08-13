package traffic

import (
	"sort"
	"sync"
	"time"
)

const (
	DefaultCapacity = 512
	DefaultWindow   = 5 * time.Minute
)

type Event struct {
	ObservedAt      string  `json:"observed_at"`
	RequestID       string  `json:"request_id"`
	ClientIP        string  `json:"client_ip"`
	Method          string  `json:"method"`
	Host            string  `json:"host"`
	Path            string  `json:"path"`
	PathFingerprint string  `json:"path_fingerprint,omitempty"`
	Route           string  `json:"route"`
	Action          string  `json:"action"`
	Reason          string  `json:"reason,omitempty"`
	Status          int     `json:"status"`
	DurationMS      float64 `json:"duration_ms"`
	CacheStatus     string  `json:"cache_status,omitempty"`
}

type Snapshot struct {
	GeneratedAt      string `json:"generated_at"`
	WindowSeconds    int64  `json:"window_seconds"`
	Status           string `json:"status"`
	Summary          string `json:"summary"`
	LastObservedAt   string `json:"last_observed_at,omitempty"`
	RequestsInWindow int    `json:"requests_in_window"`
	UniqueClients    int    `json:"unique_clients"`
	Allowed          int    `json:"allowed"`
	Rejected         int    `json:"rejected"`
	Canceled         int    `json:"canceled"`
	LastRequest      *Event `json:"last_request,omitempty"`
}

type Tracker struct {
	mu       sync.RWMutex
	capacity int
	window   time.Duration
	events   []Event
}

func New(capacity int, window time.Duration) *Tracker {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if window <= 0 {
		window = DefaultWindow
	}
	return &Tracker{capacity: capacity, window: window, events: make([]Event, 0, capacity)}
}

func (t *Tracker) Observe(event Event) {
	if event.ObservedAt == "" {
		event.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) == t.capacity {
		copy(t.events, t.events[1:])
		t.events[len(t.events)-1] = event
		return
	}
	t.events = append(t.events, event)
}

func (t *Tracker) Snapshot(now time.Time) Snapshot {
	t.mu.RLock()
	events := append([]Event(nil), t.events...)
	window := t.window
	t.mu.RUnlock()

	now = now.UTC()
	cutoff := now.Add(-window)
	out := Snapshot{
		GeneratedAt:   now.Format(time.RFC3339Nano),
		WindowSeconds: int64(window.Seconds()),
		Status:        "no_recent_traffic",
		Summary:       "No client requests have been observed during the recent activity window.",
	}
	clients := map[string]struct{}{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
		if err != nil || observed.Before(cutoff) {
			continue
		}
		if out.LastRequest == nil {
			copy := event
			out.LastRequest = &copy
			out.LastObservedAt = event.ObservedAt
		}
		out.RequestsInWindow++
		if event.ClientIP != "" {
			clients[event.ClientIP] = struct{}{}
		}
		if event.Action == "ALLOW" || event.Action == "LOG" {
			out.Allowed++
		} else if event.Action == "CANCELED" {
			out.Canceled++
		} else {
			out.Rejected++
		}
	}
	out.UniqueClients = len(clients)
	if out.LastRequest != nil {
		out.Status = "traffic_observed"
		out.Summary = "Recent client traffic is reaching SecurityEdge; completed security decisions and cancellations are summarized separately."
	}
	return out
}

func (t *Tracker) Recent(limit int) []Event {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if limit <= 0 || limit > len(t.events) {
		limit = len(t.events)
	}
	out := append([]Event(nil), t.events[len(t.events)-limit:]...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt > out[j].ObservedAt })
	return out
}
