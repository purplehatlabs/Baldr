package findings

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type cloneCacheEntry struct {
	path      string
	expiresAt time.Time
}

type cloneCache struct {
	mu      sync.Mutex
	entries map[uuid.UUID]cloneCacheEntry
	ttl     time.Duration
}

var globalCloneCache = &cloneCache{
	entries: make(map[uuid.UUID]cloneCacheEntry),
	ttl:     time.Hour,
}

func (c *cloneCache) Get(repoID uuid.UUID) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[repoID]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			_ = os.RemoveAll(entry.path)
			delete(c.entries, repoID)
		}
		return "", false
	}
	return entry.path, true
}

func (c *cloneCache) Put(repoID uuid.UUID, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[repoID]; ok && old.path != path {
		_ = os.RemoveAll(old.path)
	}
	c.entries[repoID] = cloneCacheEntry{
		path:      path,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *cloneCache) Release(repoID uuid.UUID, path string, keepCached bool) {
	if keepCached {
		c.Put(repoID, path)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[repoID]; ok && entry.path == path {
		return
	}
	_ = os.RemoveAll(path)
}

func analysisWorkDir() string {
	dir := filepath.Join(os.TempDir(), "devsecops-analysis")
	_ = os.MkdirAll(dir, 0750)
	return dir
}
