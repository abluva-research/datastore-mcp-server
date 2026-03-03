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

package resources

import (
	"context"
	"fmt"
	"log"

	"github.com/googleapis/genai-toolbox/internal/sources"
)

// DynamicSourceProvider wraps a ResourceManager and can override a specific
// source with a dynamically-created source using per-request credentials.
// It implements the tools.SourceProvider interface.
type DynamicSourceProvider struct {
	delegate       *ResourceManager
	dynamicSource  sources.Source
	targetSource   string // The source name to override
}

// NewDynamicSourceProvider creates a provider that overrides the specified source
// with a dynamic source, falling back to the ResourceManager for all other sources.
func NewDynamicSourceProvider(delegate *ResourceManager, cache *sources.DynamicSourceCache, ctx context.Context, creds *sources.DynamicCredentials, targetSourceName string) (*DynamicSourceProvider, error) {
	// Determine source type from the existing source
	existingSource, ok := delegate.GetSource(targetSourceName)
	if !ok {
		return nil, fmt.Errorf("source %q not found in resource manager", targetSourceName)
	}

	sourceType := existingSource.SourceType()

	// Create or retrieve cached dynamic source
	dynSource, err := cache.GetOrCreate(ctx, creds, sourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic source for %q: %w", targetSourceName, err)
	}

	log.Printf("Dynamic source provider created: source=%s user=%s host=%s db=%s",
		targetSourceName, creds.User, creds.Host, creds.Database)

	return &DynamicSourceProvider{
		delegate:      delegate,
		dynamicSource: dynSource,
		targetSource:  targetSourceName,
	}, nil
}

// GetSource returns the dynamic source if the name matches the target,
// otherwise falls back to the delegate ResourceManager.
func (p *DynamicSourceProvider) GetSource(sourceName string) (sources.Source, bool) {
	if sourceName == p.targetSource && p.dynamicSource != nil {
		return p.dynamicSource, true
	}
	return p.delegate.GetSource(sourceName)
}
