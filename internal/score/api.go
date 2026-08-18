package score

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
)

// DefaultBaseURL is the public scoring endpoint. Override with --api-url or the
// HARBINGER_API_URL env var (e.g. for a self-hosted server).
const DefaultBaseURL = "https://api.harbingerlabs.ai"

// API posts tokenized features to the Harbinger server. It transmits ONLY the
// features.ScoreRequest — nothing else. See internal/features for exactly what
// that contains, and use `harbinger analyze --show-payload` to inspect it.
type API struct {
	BaseURL   string
	APIKey    string
	Client    *http.Client
	ClientVer string
}

// NewAPI constructs an API scorer with a sane timeout.
func NewAPI(baseURL, apiKey, clientVer string) *API {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &API{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		ClientVer: clientVer,
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *API) Name() string    { return "server-full (" + a.BaseURL + ")" }
func (a *API) Transmits() bool { return true }

func (a *API) Score(ctx context.Context, req *features.ScoreRequest) (*Response, error) {
	return doPost[Response](ctx, a, "/v1/score", req)
}

// APIError carries an actionable server error.
type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("server %d %s: %s (retry after %s)", e.Status, e.Code, e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("server %d %s: %s", e.Status, e.Code, e.Message)
}

func doPost[T any](ctx context.Context, a *API, path string, body any) (*T, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.APIKey)
	httpReq.Header.Set("User-Agent", "harbinger-cli/"+a.ClientVer)

	resp, err := a.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cannot reach Harbinger server (%s): %w — use --offline to score locally", a.BaseURL, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if resp.StatusCode != http.StatusOK {
		ae := &APIError{Status: resp.StatusCode}
		var body struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &body)
		ae.Code, ae.Message = body.Code, body.Message
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, e := time.ParseDuration(ra + "s"); e == nil {
				ae.RetryAfter = secs
			}
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			if ae.Message == "" {
				ae.Message = "invalid or expired API key"
			}
		case http.StatusUpgradeRequired:
			if ae.Message == "" {
				ae.Message = "client too old for the current model — please update harbinger"
			}
		case http.StatusTooManyRequests:
			if ae.Message == "" {
				ae.Message = "rate limit reached for this tier"
			}
		}
		return nil, ae
	}

	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("malformed server response: %w", err)
	}
	return &out, nil
}
