package models

import "time"

type WebTarget struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	Name               string         `json:"name"`
	TargetType         string         `json:"target_type"`
	BaseURL            string         `json:"base_url"`
	APISchemaURL       string         `json:"api_schema_url,omitempty"`
	InScopePatterns    []string       `json:"in_scope_patterns,omitempty"`
	OutOfScopePatterns []string       `json:"out_of_scope_patterns,omitempty"`
	Labels             map[string]any `json:"labels,omitempty"`
	CreatedBy          string         `json:"created_by"`
	UpdatedBy          string         `json:"updated_by"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type CreateWebTargetRequest struct {
	Name               string         `json:"name"`
	TargetType         string         `json:"target_type"`
	BaseURL            string         `json:"base_url"`
	APISchemaURL       string         `json:"api_schema_url"`
	InScopePatterns    []string       `json:"in_scope_patterns"`
	OutOfScopePatterns []string       `json:"out_of_scope_patterns"`
	Labels             map[string]any `json:"labels,omitempty"`
}

type UpdateWebTargetRequest struct {
	Name               string         `json:"name"`
	TargetType         string         `json:"target_type"`
	BaseURL            string         `json:"base_url"`
	APISchemaURL       string         `json:"api_schema_url"`
	InScopePatterns    []string       `json:"in_scope_patterns"`
	OutOfScopePatterns []string       `json:"out_of_scope_patterns"`
	Labels             map[string]any `json:"labels,omitempty"`
}

type WebAuthProfile struct {
	ID                   string           `json:"id"`
	TenantID             string           `json:"tenant_id"`
	Name                 string           `json:"name"`
	AuthType             string           `json:"auth_type"`
	LoginURL             string           `json:"login_url,omitempty"`
	UsernameSecretRef    string           `json:"username_secret_ref,omitempty"`
	PasswordSecretRef    string           `json:"password_secret_ref,omitempty"`
	BearerTokenSecretRef string           `json:"bearer_token_secret_ref,omitempty"`
	CSRFMode             string           `json:"csrf_mode,omitempty"`
	SessionBootstrap     map[string]any   `json:"session_bootstrap,omitempty"`
	TestPersonas         []map[string]any `json:"test_personas,omitempty"`
	TokenRefreshStrategy string           `json:"token_refresh_strategy,omitempty"`
	Enabled              bool             `json:"enabled"`
	CreatedBy            string           `json:"created_by"`
	UpdatedBy            string           `json:"updated_by"`
	CreatedAt            time.Time        `json:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at"`
}

type CreateWebAuthProfileRequest struct {
	Name                 string           `json:"name"`
	AuthType             string           `json:"auth_type"`
	LoginURL             string           `json:"login_url"`
	UsernameSecretRef    string           `json:"username_secret_ref"`
	PasswordSecretRef    string           `json:"password_secret_ref"`
	BearerTokenSecretRef string           `json:"bearer_token_secret_ref"`
	CSRFMode             string           `json:"csrf_mode"`
	SessionBootstrap     map[string]any   `json:"session_bootstrap,omitempty"`
	TestPersonas         []map[string]any `json:"test_personas,omitempty"`
	TokenRefreshStrategy string           `json:"token_refresh_strategy"`
	Enabled              *bool            `json:"enabled"`
}

type UpdateWebAuthProfileRequest struct {
	Name                 string           `json:"name"`
	AuthType             string           `json:"auth_type"`
	LoginURL             string           `json:"login_url"`
	UsernameSecretRef    string           `json:"username_secret_ref"`
	PasswordSecretRef    string           `json:"password_secret_ref"`
	BearerTokenSecretRef string           `json:"bearer_token_secret_ref"`
	CSRFMode             string           `json:"csrf_mode"`
	SessionBootstrap     map[string]any   `json:"session_bootstrap,omitempty"`
	TestPersonas         []map[string]any `json:"test_personas,omitempty"`
	TokenRefreshStrategy string           `json:"token_refresh_strategy"`
	Enabled              *bool            `json:"enabled"`
}

type WebCrawlPolicy struct {
	ID                     string         `json:"id"`
	TenantID               string         `json:"tenant_id"`
	WebTargetID            string         `json:"web_target_id"`
	AuthProfileID          string         `json:"auth_profile_id,omitempty"`
	SafeMode               bool           `json:"safe_mode"`
	MaxDepth               int64          `json:"max_depth"`
	MaxRequests            int64          `json:"max_requests"`
	RequestBudgetPerMinute int64          `json:"request_budget_per_minute"`
	AllowPaths             []string       `json:"allow_paths,omitempty"`
	DenyPaths              []string       `json:"deny_paths,omitempty"`
	SeedURLs               []string       `json:"seed_urls,omitempty"`
	Headers                map[string]any `json:"headers,omitempty"`
	CreatedBy              string         `json:"created_by"`
	UpdatedBy              string         `json:"updated_by"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

type UpsertWebCrawlPolicyRequest struct {
	AuthProfileID          string         `json:"auth_profile_id"`
	SafeMode               *bool          `json:"safe_mode"`
	MaxDepth               *int64         `json:"max_depth"`
	MaxRequests            *int64         `json:"max_requests"`
	RequestBudgetPerMinute *int64         `json:"request_budget_per_minute"`
	AllowPaths             []string       `json:"allow_paths"`
	DenyPaths              []string       `json:"deny_paths"`
	SeedURLs               []string       `json:"seed_urls"`
	Headers                map[string]any `json:"headers,omitempty"`
}

type WebCoverageBaseline struct {
	ID                        string    `json:"id"`
	TenantID                  string    `json:"tenant_id"`
	WebTargetID               string    `json:"web_target_id"`
	ExpectedRouteCount        int64     `json:"expected_route_count"`
	ExpectedAPIOperationCount int64     `json:"expected_api_operation_count"`
	ExpectedAuthStateCount    int64     `json:"expected_auth_state_count"`
	MinimumRouteCoverage      float64   `json:"minimum_route_coverage"`
	MinimumAPICoverage        float64   `json:"minimum_api_coverage"`
	MinimumAuthCoverage       float64   `json:"minimum_auth_coverage"`
	Notes                     string    `json:"notes,omitempty"`
	CreatedBy                 string    `json:"created_by"`
	UpdatedBy                 string    `json:"updated_by"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type UpsertWebCoverageBaselineRequest struct {
	ExpectedRouteCount        *int64   `json:"expected_route_count"`
	ExpectedAPIOperationCount *int64   `json:"expected_api_operation_count"`
	ExpectedAuthStateCount    *int64   `json:"expected_auth_state_count"`
	MinimumRouteCoverage      *float64 `json:"minimum_route_coverage"`
	MinimumAPICoverage        *float64 `json:"minimum_api_coverage"`
	MinimumAuthCoverage       *float64 `json:"minimum_auth_coverage"`
	Notes                     string   `json:"notes"`
}

type WebTargetScopeEvaluation struct {
	WebTargetID string `json:"web_target_id"`
	URL         string `json:"url"`
	InScope     bool   `json:"in_scope"`
	Reason      string `json:"reason,omitempty"`
}

type RunWebTargetRequest struct {
	Profile string   `json:"profile"`
	Tools   []string `json:"tools"`
}

type WebRuntimeCoverageRun struct {
	ID                          string    `json:"id"`
	TenantID                    string    `json:"tenant_id"`
	WebTargetID                 string    `json:"web_target_id"`
	ScanJobID                   string    `json:"scan_job_id,omitempty"`
	RouteCoverage               float64   `json:"route_coverage"`
	APICoverage                 float64   `json:"api_coverage"`
	AuthCoverage                float64   `json:"auth_coverage"`
	DiscoveredRouteCount        int64     `json:"discovered_route_count"`
	DiscoveredAPIOperationCount int64     `json:"discovered_api_operation_count"`
	DiscoveredAuthStateCount    int64     `json:"discovered_auth_state_count"`
	EvidenceRef                 string    `json:"evidence_ref,omitempty"`
	CreatedBy                   string    `json:"created_by"`
	CreatedAt                   time.Time `json:"created_at"`
}

type CreateWebRuntimeCoverageRunRequest struct {
	ScanJobID                   string  `json:"scan_job_id"`
	RouteCoverage               float64 `json:"route_coverage"`
	APICoverage                 float64 `json:"api_coverage"`
	AuthCoverage                float64 `json:"auth_coverage"`
	DiscoveredRouteCount        int64   `json:"discovered_route_count"`
	DiscoveredAPIOperationCount int64   `json:"discovered_api_operation_count"`
	DiscoveredAuthStateCount    int64   `json:"discovered_auth_state_count"`
	EvidenceRef                 string  `json:"evidence_ref"`
}

type WebCoverageStatus struct {
	WebTargetID        string                 `json:"web_target_id"`
	Baseline           *WebCoverageBaseline   `json:"baseline,omitempty"`
	LatestRun          *WebRuntimeCoverageRun `json:"latest_run,omitempty"`
	RouteCoverageMeets bool                   `json:"route_coverage_meets"`
	APICoverageMeets   bool                   `json:"api_coverage_meets"`
	AuthCoverageMeets  bool                   `json:"auth_coverage_meets"`
	OverallMeets       bool                   `json:"overall_meets"`
}
