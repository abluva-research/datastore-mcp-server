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

package postgres

import (
	"context"
	"fmt"
	"net/url"

	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/jackc/pgx/v5/pgxpool"
)

func init() {
	sources.RegisterDynamicFactory(SourceType, newDynamicSource)
}

// newDynamicSource creates a PostgreSQL source with dynamically provided credentials.
func newDynamicSource(ctx context.Context, name string, creds *sources.DynamicCredentials) (sources.Source, error) {
	port := creds.Port
	if port == "" {
		port = "5432"
	}

	connURL := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(creds.User, creds.Password),
		Host:     fmt.Sprintf("%s:%s", creds.Host, port),
		Path:     creds.Database,
		RawQuery: "sslmode=disable",
	}

	config, err := pgxpool.ParseConfig(connURL.String())
	if err != nil {
		return nil, fmt.Errorf("unable to parse dynamic connection uri: %w", err)
	}

	// Limit dynamic pool size for safety
	config.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic connection pool: %w", err)
	}

	// Verify connectivity
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to connect with dynamic credentials: %w", err)
	}

	cfg := Config{
		Name:     name,
		Type:     SourceType,
		Host:     creds.Host,
		Port:     port,
		User:     creds.User,
		Password: "***", // Don't store the real password in config
		Database: creds.Database,
	}

	return &Source{
		Config: cfg,
		Pool:   pool,
	}, nil
}
