package cache

import (
	"container/list"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	StoredAt   time.Time
	ExpiresAt  time.Time
	StaleUntil time.Time
}

func (e Entry) Size() int64 {
	size := int64(len(e.Body))
	for k, values := range e.Header {
		size += int64(len(k))
		for _, value := range values {
			size += int64(len(value))
		}
	}
	return size
}

type item struct {
	key   string
	entry Entry
	size  int64
}

type Stats struct {
	Entries   int    `json:"entries"`
	Bytes     int64  `json:"bytes"`
	Evictions uint64 `json:"evictions"`
}

type Cache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int64
	bytes      int64
	ll         *list.List
	items      map[string]*list.Element
	evictions  uint64
}

func New(maxEntries int, maxBytes int64) *Cache {
	return &Cache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ll:         list.New(),
		items:      make(map[string]*list.Element),
	}
}

// Get returns an entry and whether it is fresh or stale-but-usable.
func (c *Cache) Get(key string, now time.Time) (entry Entry, fresh bool, stale bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return Entry{}, false, false
	}
	it := elem.Value.(*item)
	if now.After(it.entry.StaleUntil) {
		c.removeElement(elem, false)
		return Entry{}, false, false
	}
	c.ll.MoveToFront(elem)
	copied := cloneEntry(it.entry)
	if now.Before(it.entry.ExpiresAt) || now.Equal(it.entry.ExpiresAt) {
		return copied, true, false
	}
	return copied, false, true
}

func (c *Cache) Set(key string, entry Entry) bool {
	size := entry.Size()
	if size <= 0 || size > c.maxBytes {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem, false)
	}
	elem := c.ll.PushFront(&item{key: key, entry: cloneEntry(entry), size: size})
	c.items[key] = elem
	c.bytes += size

	for c.ll.Len() > c.maxEntries || c.bytes > c.maxBytes {
		c.removeOldest()
	}
	return true
}

func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return false
	}
	c.removeElement(elem, false)
	return true
}

func (c *Cache) Purge(host, pathPrefix string, keyRequest func(string) (string, string, bool)) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	host = strings.ToLower(strings.TrimSpace(host))
	for key, elem := range c.items {
		keyHost, requestURI, ok := keyRequest(key)
		if !ok {
			continue
		}
		if host != "" && keyHost != host {
			continue
		}
		if pathPrefix != "" && !purgePathMatches(requestURI, pathPrefix) {
			continue
		}
		c.removeElement(elem, false)
		count++
	}
	return count
}

// PurgeRequest removes every cached representation of one exact request URI.
// Cache keys may contain multiple Vary-header variants, so invalidation must
// remove all matching keys rather than deleting a single computed key.
func (c *Cache) PurgeRequest(host, requestURI string, keyRequest func(string) (string, string, bool)) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	host = strings.ToLower(strings.TrimSpace(host))
	count := 0
	for key, elem := range c.items {
		keyHost, keyURI, ok := keyRequest(key)
		if !ok || keyHost != host || keyURI != requestURI {
			continue
		}
		c.removeElement(elem, false)
		count++
	}
	return count
}

func purgePathMatches(requestURI, prefix string) bool {
	parsed, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return false
	}
	requestPath := canonicalRequestPath(parsed.Path)
	if prefix == "/" || requestPath == prefix {
		return true
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}

func canonicalRequestPath(value string) string {
	if value == "" {
		return "/"
	}
	trailingSlash := strings.HasSuffix(value, "/")
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func (c *Cache) Clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := len(c.items)
	c.ll.Init()
	c.items = make(map[string]*list.Element)
	c.bytes = 0
	return count
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Entries: c.ll.Len(), Bytes: c.bytes, Evictions: c.evictions}
}

func (c *Cache) removeOldest() {
	elem := c.ll.Back()
	if elem != nil {
		c.removeElement(elem, true)
	}
}

func (c *Cache) removeElement(elem *list.Element, eviction bool) {
	it := elem.Value.(*item)
	delete(c.items, it.key)
	c.ll.Remove(elem)
	c.bytes -= it.size
	if eviction {
		c.evictions++
	}
}

func cloneEntry(in Entry) Entry {
	out := in
	out.Header = in.Header.Clone()
	out.Body = append([]byte(nil), in.Body...)
	return out
}
