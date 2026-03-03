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

//go:build slim

package internal

import (
	// Import prompt packages for side effect of registration
	_ "github.com/googleapis/genai-toolbox/internal/prompts/custom"

	// Import PostgreSQL tool packages only
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgresdatabaseoverview"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgresexecutesql"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgresgetcolumncardinality"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistactivequeries"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistavailableextensions"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistdatabasestats"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistindexes"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistinstalledextensions"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistlocks"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistpgsettings"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistpublicationtables"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistquerystats"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistroles"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistschemas"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistsequences"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgresliststoredprocedure"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslisttables"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslisttablespaces"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslisttablestats"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslisttriggers"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslistviews"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgreslongrunningtransactions"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgresreplicationstats"
	_ "github.com/googleapis/genai-toolbox/internal/tools/postgres/postgressql"
	_ "github.com/googleapis/genai-toolbox/internal/tools/http"

	// Import PostgreSQL source only
	_ "github.com/googleapis/genai-toolbox/internal/sources/postgres"
	_ "github.com/googleapis/genai-toolbox/internal/sources/http"
)
