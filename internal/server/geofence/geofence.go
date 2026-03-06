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

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GeoInfo holds the detected geolocation information for an IP address.
type GeoInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"regionName"`
	Country string `json:"country"`
	Status  string `json:"status"`
}

// PseudoKeyGeoPolicy holds the geo-fencing policy for a pseudo key.
type PseudoKeyGeoPolicy struct {
	GeoFenceEnabled bool   `json:"geo_fence_enabled"`
	GeoFenceRegion  string `json:"geo_fence_region"`
	Valid           bool   `json:"valid"`
	Reason          string `json:"reason,omitempty"`
}

// cachedGeo is a geo lookup result with expiry.
type cachedGeo struct {
	info      *GeoInfo
	expiresAt time.Time
}

// cachedPolicy is a pseudo key geo policy result with expiry.
type cachedPolicy struct {
	policy    *PseudoKeyGeoPolicy
	expiresAt time.Time
}

// Checker performs geo-fence enforcement for pseudo key requests.
// It caches public IP detection, geo lookups, and pseudo key policies.
type Checker struct {
	mu             sync.RWMutex
	publicIP       string // cached public IP for stdio mode
	publicIPGeo    *GeoInfo
	publicIPCached bool

	geoCache    map[string]*cachedGeo    // IP -> geo info
	policyCache map[string]*cachedPolicy // virtualIdentity -> geo policy

	backendURL string // e.g. "https://172.16.1.86:4001"
	httpClient *http.Client

	geoCacheTTL    time.Duration
	policyCacheTTL time.Duration
}

// NewChecker creates a new geo-fence checker.
// backendURL is the base URL of the backend API server (e.g. "https://172.16.1.86:4001").
func NewChecker(backendURL string) *Checker {
	return &Checker{
		geoCache:    make(map[string]*cachedGeo),
		policyCache: make(map[string]*cachedPolicy),
		backendURL:  strings.TrimRight(backendURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		geoCacheTTL:    24 * time.Hour,
		policyCacheTTL: 5 * time.Minute,
	}
}

// DetectPublicIP detects the machine's public IP via api.ipify.org.
// Result is cached for the lifetime of the process (stdio session).
func (c *Checker) DetectPublicIP() (string, error) {
	c.mu.RLock()
	if c.publicIPCached {
		ip := c.publicIP
		c.mu.RUnlock()
		return ip, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.publicIPCached {
		return c.publicIP, nil
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "", fmt.Errorf("failed to detect public IP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api.ipify.org returned status %d", resp.StatusCode)
	}

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse public IP response: %w", err)
	}

	c.publicIP = result.IP
	c.publicIPCached = true
	return c.publicIP, nil
}

// LookupGeo looks up geolocation for an IP address via ip-api.com.
// Results are cached for geoCacheTTL (24 hours by default).
func (c *Checker) LookupGeo(ip string) (*GeoInfo, error) {
	if ip == "" {
		return &GeoInfo{}, nil
	}

	c.mu.RLock()
	if cached, ok := c.geoCache[ip]; ok && time.Now().Before(cached.expiresAt) {
		info := cached.info
		c.mu.RUnlock()
		return info, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check
	if cached, ok := c.geoCache[ip]; ok && time.Now().Before(cached.expiresAt) {
		return cached.info, nil
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,city,regionName,country", ip))
	if err != nil {
		// Non-blocking: return empty geo on failure
		info := &GeoInfo{IP: ip}
		c.geoCache[ip] = &cachedGeo{info: info, expiresAt: time.Now().Add(5 * time.Minute)}
		return info, nil
	}
	defer resp.Body.Close()

	var info GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		info = GeoInfo{IP: ip}
	}
	info.IP = ip

	c.geoCache[ip] = &cachedGeo{info: &info, expiresAt: time.Now().Add(c.geoCacheTTL)}
	return &info, nil
}

// GetPublicIPGeo detects public IP and looks up its geo (for stdio mode).
// Both results are cached.
func (c *Checker) GetPublicIPGeo() (*GeoInfo, error) {
	c.mu.RLock()
	if c.publicIPGeo != nil {
		geo := c.publicIPGeo
		c.mu.RUnlock()
		return geo, nil
	}
	c.mu.RUnlock()

	ip, err := c.DetectPublicIP()
	if err != nil {
		return nil, err
	}

	geo, err := c.LookupGeo(ip)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.publicIPGeo = geo
	c.mu.Unlock()

	return geo, nil
}

// ValidatePseudoKey calls the backend API to validate a pseudo key and get its geo policy.
// Results are cached for policyCacheTTL (5 minutes by default).
func (c *Checker) ValidatePseudoKey(virtualIdentity string) (*PseudoKeyGeoPolicy, error) {
	if virtualIdentity == "" {
		return &PseudoKeyGeoPolicy{Valid: true, GeoFenceEnabled: false}, nil
	}

	c.mu.RLock()
	if cached, ok := c.policyCache[virtualIdentity]; ok && time.Now().Before(cached.expiresAt) {
		policy := cached.policy
		c.mu.RUnlock()
		return policy, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check
	if cached, ok := c.policyCache[virtualIdentity]; ok && time.Now().Before(cached.expiresAt) {
		return cached.policy, nil
	}

	// Call backend validate endpoint
	payload := fmt.Sprintf(`{"pseudo_key":"%s"}`, virtualIdentity)
	resp, err := c.httpClient.Post(
		c.backendURL+"/api/pseudo-keys/validate",
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		// On failure, allow the request (fail-open)
		policy := &PseudoKeyGeoPolicy{Valid: true, GeoFenceEnabled: false}
		c.policyCache[virtualIdentity] = &cachedPolicy{policy: policy, expiresAt: time.Now().Add(1 * time.Minute)}
		return policy, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		policy := &PseudoKeyGeoPolicy{Valid: true, GeoFenceEnabled: false}
		c.policyCache[virtualIdentity] = &cachedPolicy{policy: policy, expiresAt: time.Now().Add(1 * time.Minute)}
		return policy, nil
	}

	var result struct {
		Success         bool   `json:"success"`
		Valid           bool   `json:"valid"`
		Reason          string `json:"reason"`
		GeoFenceEnabled bool   `json:"geo_fence_enabled"`
		GeoFenceRegion  string `json:"geo_fence_region"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		policy := &PseudoKeyGeoPolicy{Valid: true, GeoFenceEnabled: false}
		c.policyCache[virtualIdentity] = &cachedPolicy{policy: policy, expiresAt: time.Now().Add(1 * time.Minute)}
		return policy, nil
	}

	policy := &PseudoKeyGeoPolicy{
		Valid:           result.Valid,
		Reason:          result.Reason,
		GeoFenceEnabled: result.GeoFenceEnabled,
		GeoFenceRegion:  result.GeoFenceRegion,
	}
	c.policyCache[virtualIdentity] = &cachedPolicy{policy: policy, expiresAt: time.Now().Add(c.policyCacheTTL)}
	return policy, nil
}

// regionMatches checks if the detected country matches the allowed geo-fence region.
// Supports country names (e.g. "India") and region codes (e.g. "APAC", "US", "EU").
// isoCodeToCountry maps ISO 3166-1 alpha-2 codes to country names (uppercase).
var isoCodeToCountry = map[string]string{
	"IN": "INDIA", "CN": "CHINA", "JP": "JAPAN", "AU": "AUSTRALIA",
	"SG": "SINGAPORE", "KR": "SOUTH KOREA", "ID": "INDONESIA",
	"TH": "THAILAND", "VN": "VIETNAM", "MY": "MALAYSIA",
	"PH": "PHILIPPINES", "NZ": "NEW ZEALAND", "TW": "TAIWAN",
	"HK": "HONG KONG", "BD": "BANGLADESH", "PK": "PAKISTAN",
	"LK": "SRI LANKA", "NP": "NEPAL", "MM": "MYANMAR",
	"DE": "GERMANY", "FR": "FRANCE", "IT": "ITALY", "ES": "SPAIN",
	"NL": "NETHERLANDS", "BE": "BELGIUM", "AT": "AUSTRIA",
	"SE": "SWEDEN", "DK": "DENMARK", "FI": "FINLAND",
	"IE": "IRELAND", "PT": "PORTUGAL", "GR": "GREECE",
	"PL": "POLAND", "CZ": "CZECH REPUBLIC", "RO": "ROMANIA",
	"HU": "HUNGARY", "HR": "CROATIA", "SK": "SLOVAKIA",
	"SI": "SLOVENIA", "BG": "BULGARIA", "LT": "LITHUANIA",
	"LV": "LATVIA", "EE": "ESTONIA", "LU": "LUXEMBOURG",
	"MT": "MALTA", "CY": "CYPRUS", "GB": "UNITED KINGDOM",
	"CH": "SWITZERLAND", "NO": "NORWAY",
	"US": "UNITED STATES", "CA": "CANADA", "MX": "MEXICO",
	"BR": "BRAZIL", "AR": "ARGENTINA", "CL": "CHILE",
	"CO": "COLOMBIA", "PE": "PERU", "ZA": "SOUTH AFRICA",
	"NG": "NIGERIA", "EG": "EGYPT", "KE": "KENYA",
	"AE": "UNITED ARAB EMIRATES", "SA": "SAUDI ARABIA",
	"IL": "ISRAEL", "TR": "TURKEY", "RU": "RUSSIA",
	"UA": "UKRAINE",
}

// countryToISOCode is the reverse mapping (country name → ISO code).
var countryToISOCode = func() map[string]string {
	m := make(map[string]string, len(isoCodeToCountry))
	for code, name := range isoCodeToCountry {
		m[name] = code
	}
	return m
}()

// normalizeToCountryName resolves an ISO code or country name to uppercase country name.
func normalizeToCountryName(input string) string {
	upper := strings.ToUpper(strings.TrimSpace(input))
	if name, ok := isoCodeToCountry[upper]; ok {
		return name
	}
	return upper
}

func regionMatches(detectedCountry string, allowedRegion string) bool {
	if detectedCountry == "" || allowedRegion == "" {
		return false
	}

	detected := normalizeToCountryName(detectedCountry)
	allowed := strings.ToUpper(strings.TrimSpace(allowedRegion))

	// Resolve allowed region if it's an ISO code (e.g. "IN" → "INDIA")
	allowedResolved := normalizeToCountryName(allowedRegion)

	// Direct match (after normalizing both sides)
	if detected == allowedResolved {
		return true
	}

	// Region group mappings
	apacCountries := map[string]bool{
		"INDIA": true, "CHINA": true, "JAPAN": true, "AUSTRALIA": true,
		"SINGAPORE": true, "SOUTH KOREA": true, "INDONESIA": true,
		"THAILAND": true, "VIETNAM": true, "MALAYSIA": true,
		"PHILIPPINES": true, "NEW ZEALAND": true, "TAIWAN": true,
		"HONG KONG": true, "BANGLADESH": true, "PAKISTAN": true,
		"SRI LANKA": true, "NEPAL": true, "MYANMAR": true,
	}
	euCountries := map[string]bool{
		"GERMANY": true, "FRANCE": true, "ITALY": true, "SPAIN": true,
		"NETHERLANDS": true, "BELGIUM": true, "AUSTRIA": true,
		"SWEDEN": true, "DENMARK": true, "FINLAND": true,
		"IRELAND": true, "PORTUGAL": true, "GREECE": true,
		"POLAND": true, "CZECH REPUBLIC": true, "ROMANIA": true,
		"HUNGARY": true, "CROATIA": true, "SLOVAKIA": true,
		"SLOVENIA": true, "BULGARIA": true, "LITHUANIA": true,
		"LATVIA": true, "ESTONIA": true, "LUXEMBOURG": true,
		"MALTA": true, "CYPRUS": true, "UNITED KINGDOM": true,
		"SWITZERLAND": true, "NORWAY": true,
	}

	switch allowed {
	case "APAC":
		return apacCountries[detected]
	case "EU", "EUROPE":
		return euCountries[detected]
	case "US", "USA", "UNITED STATES":
		return detected == "UNITED STATES"
	}

	return false
}

// GeoFenceResult holds the outcome of a geo-fence check with full context for logging.
type GeoFenceResult struct {
	Allowed         bool
	Blocked         bool
	BlockReason     string
	DetectedCountry string
	AllowedRegion   string
	ClientIP        string
	ClientCity      string
	ClientRegion    string
	GeoFenceEnabled bool
	PseudoKey       string
}

// CheckGeoFence performs the full geo-fence check.
// For stdio mode: isStdio=true, clientIP and clientRegion can be empty (auto-detected).
// For HTTP mode: isStdio=false, clientIP/clientRegion should come from the client request.
// Returns nil if allowed, or an error with a clear message if blocked.
func (c *Checker) CheckGeoFence(virtualIdentity string, isStdio bool, clientIP string, clientRegion string) error {
	result := c.CheckGeoFenceWithResult(virtualIdentity, isStdio, clientIP, clientRegion)
	if result.Blocked {
		return fmt.Errorf("%s", result.BlockReason)
	}
	return nil
}

// CheckGeoFenceWithResult performs the full geo-fence check and returns a rich result
// with geo information, decision, and context — useful for logging.
func (c *Checker) CheckGeoFenceWithResult(virtualIdentity string, isStdio bool, clientIP string, clientRegion string) *GeoFenceResult {
	result := &GeoFenceResult{PseudoKey: virtualIdentity, ClientIP: clientIP}

	if virtualIdentity == "" {
		result.Allowed = true
		return result
	}

	// Get pseudo key policy
	policy, err := c.ValidatePseudoKey(virtualIdentity)
	if err != nil {
		result.Allowed = true // Fail-open on backend errors
		return result
	}

	if !policy.Valid {
		result.Blocked = true
		result.BlockReason = fmt.Sprintf("pseudo key validation failed: %s", policy.Reason)
		return result
	}

	if !policy.GeoFenceEnabled || policy.GeoFenceRegion == "" {
		result.Allowed = true
		return result
	}

	result.GeoFenceEnabled = true
	result.AllowedRegion = policy.GeoFenceRegion

	// Determine the client's country
	if clientRegion != "" {
		result.DetectedCountry = clientRegion
	} else if clientIP != "" {
		geo, err := c.LookupGeo(clientIP)
		if err != nil || geo.Country == "" {
			result.Blocked = true
			result.BlockReason = fmt.Sprintf("geo-fence check failed: unable to determine region for IP %s", clientIP)
			return result
		}
		result.DetectedCountry = geo.Country
		result.ClientCity = geo.City
		result.ClientRegion = geo.Region
		result.ClientIP = geo.IP
	} else if isStdio {
		geo, err := c.GetPublicIPGeo()
		if err != nil || geo.Country == "" {
			result.Blocked = true
			result.BlockReason = "geo-fence check failed: unable to detect public IP for region verification"
			return result
		}
		result.DetectedCountry = geo.Country
		result.ClientCity = geo.City
		result.ClientRegion = geo.Region
		result.ClientIP = geo.IP
	} else {
		result.Blocked = true
		result.BlockReason = "geo-fence is enabled for this key but no client IP or region was provided. " +
			"Include 'x-ablv-client-ip' or 'x-ablv-client-region' in your request arguments"
		return result
	}

	// Check if detected country matches allowed region
	if !regionMatches(result.DetectedCountry, policy.GeoFenceRegion) {
		result.Blocked = true
		result.BlockReason = fmt.Sprintf(
			"geo-fence violation: access denied. Your detected region '%s' is not within the allowed region '%s' for this pseudo key",
			result.DetectedCountry, policy.GeoFenceRegion,
		)
		return result
	}

	result.Allowed = true
	return result
}

// LogToBackend sends a request log event to the backend /api/ext-proc/mcp-log endpoint.
// This is fire-and-forget (async, non-blocking).
func (c *Checker) LogToBackend(toolName, identity, identityType string, geoResult *GeoFenceResult) {
	go func() {
		logType := "allowed"
		if geoResult.Blocked {
			logType = "blocked"
		}

		payload := fmt.Sprintf(`{
			"method": "MCP",
			"host": "mcp-toolbox",
			"path": "/%s",
			"tool_name": "%s",
			"type": "%s",
			"block_reason": "%s",
			"rule_type": "mcp_geofence",
			"identity_type": "%s",
			"identity": "%s",
			"user_email": "%s",
			"provider": "MCP Toolbox",
			"pseudo_key": "%s",
			"client_ip": "%s",
			"client_city": "%s",
			"client_region": "%s",
			"client_country": "%s",
			"body_preview": "Geo-fence: region=%s allowed=%s detected=%s"
		}`,
			toolName, toolName, logType,
			escapeJSON(geoResult.BlockReason),
			identityType, escapeJSON(identity), escapeJSON(identity),
			geoResult.PseudoKey,
			geoResult.ClientIP, geoResult.ClientCity, geoResult.ClientRegion, geoResult.DetectedCountry,
			geoResult.AllowedRegion, geoResult.DetectedCountry, geoResult.DetectedCountry,
		)

		resp, err := c.httpClient.Post(
			c.backendURL+"/api/ext-proc/mcp-log",
			"application/json",
			strings.NewReader(payload),
		)
		if err != nil {
			fmt.Printf("[geofence] Failed to log to backend: %v\n", err)
			return
		}
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
	}()
}

// escapeJSON escapes a string for safe inclusion in a JSON string literal.
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}
