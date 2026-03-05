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

package geofence

import "context"

type checkerKey struct{}
type stdioKey struct{}

// WithChecker returns a new context with the geo-fence checker attached.
func WithChecker(ctx context.Context, c *Checker) context.Context {
	return context.WithValue(ctx, checkerKey{}, c)
}

// CheckerFromContext extracts the geo-fence checker from the context, if present.
func CheckerFromContext(ctx context.Context) (*Checker, bool) {
	c, ok := ctx.Value(checkerKey{}).(*Checker)
	return c, ok && c != nil
}

// WithStdio returns a new context marking this as a stdio (local) session.
func WithStdio(ctx context.Context, isStdio bool) context.Context {
	return context.WithValue(ctx, stdioKey{}, isStdio)
}

// IsStdioFromContext returns whether the current session is stdio mode.
func IsStdioFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(stdioKey{}).(bool)
	return ok && v
}
