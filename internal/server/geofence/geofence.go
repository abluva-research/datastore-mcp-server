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
func regionMatches(detectedCountry string, allowedRegion string) bool {
	if detectedCountry == "" || allowedRegion == "" {
		return false
	}

	detected := strings.ToUpper(strings.TrimSpace(detectedCountry))
	allowed := strings.ToUpper(strings.TrimSpace(allowedRegion))

	// Direct match (country name or code)
	if detected == allowed {
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
		return detected == "UNITED STATES" || detected == "US" || detected == "USA"
	}

	return false
}

// CheckGeoFence performs the full geo-fence check.
// For stdio mode: isStdio=true, clientIP and clientRegion can be empty (auto-detected).
// For HTTP mode: isStdio=false, clientIP/clientRegion should come from the client request.
// Returns nil if allowed, or an error with a clear message if blocked.
func (c *Checker) CheckGeoFence(virtualIdentity string, isStdio bool, clientIP string, clientRegion string) error {
	if virtualIdentity == "" {
		return nil // No virtual identity = no geo-fence check
	}

	// Get pseudo key policy
	policy, err := c.ValidatePseudoKey(virtualIdentity)
	if err != nil {
		return nil // Fail-open on backend errors
	}

	if !policy.Valid {
		return fmt.Errorf("pseudo key validation failed: %s", policy.Reason)
	}

	if !policy.GeoFenceEnabled || policy.GeoFenceRegion == "" {
		return nil // Geo-fencing not enabled for this key
	}

	// Determine the client's country
	var detectedCountry string

	if clientRegion != "" {
		// Client explicitly provided region (HTTP mode)
		detectedCountry = clientRegion
	} else if clientIP != "" {
		// Client provided IP but not region — look up geo
		geo, err := c.LookupGeo(clientIP)
		if err != nil || geo.Country == "" {
			return fmt.Errorf("geo-fence check failed: unable to determine region for IP %s", clientIP)
		}
		detectedCountry = geo.Country
	} else if isStdio {
		// stdio mode — auto-detect
		geo, err := c.GetPublicIPGeo()
		if err != nil || geo.Country == "" {
			return fmt.Errorf("geo-fence check failed: unable to detect public IP for region verification")
		}
		detectedCountry = geo.Country
	} else {
		// HTTP mode with no IP/region provided
		return fmt.Errorf("geo-fence is enabled for this key but no client IP or region was provided. " +
			"Include 'x-ablv-client-ip' or 'x-ablv-client-region' in your request arguments")
	}

	// Check if detected country matches allowed region
	if !regionMatches(detectedCountry, policy.GeoFenceRegion) {
		return fmt.Errorf(
			"geo-fence violation: access denied. Your detected region '%s' is not within the allowed region '%s' for this pseudo key",
			detectedCountry, policy.GeoFenceRegion,
		)
	}

	return nil
}
