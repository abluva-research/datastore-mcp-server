// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sources

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"time"
)

// DynamicCredentials holds database credentials provided at request time.
type DynamicCredentials struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// CacheKey returns a unique key for connection pool caching.
func (dc *DynamicCredentials) CacheKey() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s", dc.Host, dc.Port, dc.User, dc.Password, dc.Database)))
	return fmt.Sprintf("dyn_%x", h.Sum(nil))
}

// DynamicSourceFactory creates a Source from DynamicCredentials.
// Implementations are registered per source type (e.g., postgres).
type DynamicSourceFactory func(ctx context.Context, name string, creds *DynamicCredentials) (Source, error)

var dynamicFactoryRegistry = make(map[string]DynamicSourceFactory)

// RegisterDynamicFactory registers a factory for creating dynamic sources of a given type.
func RegisterDynamicFactory(sourceType string, factory DynamicSourceFactory) {
	dynamicFactoryRegistry[sourceType] = factory
}

// GetDynamicFactory returns the dynamic factory for a given source type.
func GetDynamicFactory(sourceType string) (DynamicSourceFactory, bool) {
	f, ok := dynamicFactoryRegistry[sourceType]
	return f, ok
}

// dynamicPoolEntry holds a cached dynamic source with its creation time.
type dynamicPoolEntry struct {
	source    Source
	createdAt time.Time
}

// DynamicSourceCache manages cached dynamic source connections.
type DynamicSourceCache struct {
	mu      sync.RWMutex
	entries map[string]*dynamicPoolEntry
	maxAge  time.Duration
}

// NewDynamicSourceCache creates a new cache with automatic cleanup.
func NewDynamicSourceCache(ctx context.Context, maxAge time.Duration) *DynamicSourceCache {
	cache := &DynamicSourceCache{
		entries: make(map[string]*dynamicPoolEntry),
		maxAge:  maxAge,
	}
	go cache.cleanupRoutine(ctx)
	return cache
}

// GetOrCreate retrieves a cached source or creates a new one.
func (c *DynamicSourceCache) GetOrCreate(ctx context.Context, creds *DynamicCredentials, sourceType string) (Source, error) {
	key := creds.CacheKey()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if ok && time.Since(entry.createdAt) < c.maxAge {
		return entry.source, nil
	}

	// Create a new dynamic source
	factory, ok := GetDynamicFactory(sourceType)
	if !ok {
		return nil, fmt.Errorf("no dynamic factory registered for source type %q", sourceType)
	}

	source, err := factory(ctx, fmt.Sprintf("dynamic-%s", key[:12]), creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic source: %w", err)
	}

	c.mu.Lock()
	c.entries[key] = &dynamicPoolEntry{
		source:    source,
		createdAt: time.Now(),
	}
	c.mu.Unlock()

	log.Printf("Dynamic source created for user=%s host=%s db=%s", creds.User, creds.Host, creds.Database)
	return source, nil
}

// cleanupRoutine removes expired entries periodically.
func (c *DynamicSourceCache) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			for key, entry := range c.entries {
				if time.Since(entry.createdAt) > c.maxAge {
					delete(c.entries, key)
					log.Printf("Dynamic source cache entry expired: %s", key[:12])
				}
			}
			c.mu.Unlock()
		}
	}
}
