package aiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Defaults chosen for a local sidecar on the same host or LAN — hexward-ai
// is never a remote cloud call, so these are deliberately short compared
// to a typical HTTP client default.
const (
	defaultTimeout      = 20 * time.Second
	defaultMaxRetries   = 2
	defaultRetryBackoff = 400 * time.Millisecond
	defaultModel        = "hexward-ai"

	// defaultMaxTokens bounds a single response. Found necessary by
	// testing against a real sidecar (SmolLM3-3B, CPU inference): with
	// no cap, a slow model generating a long "explanation" string can
	// run past a caller's own timeout even though the grammar guarantees
	// it will eventually stop — "eventually" on an unloaded CPU can be
	// well over a minute. A pilot narration answer does not need more
	// than a few hundred tokens.
	defaultMaxTokens = 512

	// DefaultBaseURL matches the registered port from spec §3/[K-3]:
	// TCP 127.0.0.1:8435, the slot after TopoLight's 8433/8434.
	DefaultBaseURL = "http://127.0.0.1:8435"
)

// ErrUnavailable means the sidecar could not be reached or did not answer
// in time: connection refused, DNS failure, timeout, or an HTTP 5xx after
// retries were exhausted. Per spec §3, this is not an error condition for
// the product as a whole — the caller is expected to render nothing in
// the AI section and continue exactly as it does when AI Assist is not
// configured at all. It is exported so callers can branch on it with
// errors.Is / IsUnavailable instead of string-matching.
var ErrUnavailable = errors.New("aiclient: hexward-ai sidecar unavailable")

// ErrInvalidRequest means the sidecar was reached and answered, but
// rejected the request (HTTP 4xx) — almost always a caller bug (wrong
// evidence shape, unknown feature) rather than the sidecar being down.
// Callers may want to log this loudly instead of silently hiding the AI
// section, which is why it is a distinct sentinel from ErrUnavailable.
var ErrInvalidRequest = errors.New("aiclient: hexward-ai rejected the request")

// ErrInvalidResponse means the sidecar answered 2xx but the body did not
// parse into the expected schema. The GBNF grammar on the server is
// supposed to make this impossible, but a grammar constrains syntax, not
// which server is actually listening on the port — this client never
// trusts that constraint alone.
var ErrInvalidResponse = errors.New("aiclient: hexward-ai returned an unparsable response")

// IsUnavailable reports whether err means "the sidecar is not there right
// now" — the one case where the documented behavior is to render nothing
// and move on without surfacing an error to the end user.
func IsUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

// Client is a small OpenAI-compatible chat-completions client scoped to
// exactly what hexward-ai needs. It is intentionally not a general
// OpenAI SDK: no streaming, no function calling, no embeddings — those
// are out of scope for a narration-only sidecar (spec §2).
type Client struct {
	baseURL      string
	httpClient   *http.Client
	model        string
	timeout      time.Duration
	maxRetries   int
	retryBackoff time.Duration
	grammar      string
	maxTokens    int
	apiKey       string
	noThinking   bool
}

// Option configures a Client constructed with New.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client. Used by tests to
// point at an httptest.Server, and by callers who need custom TLS (BYO
// mTLS endpoint per spec §3) or a corporate proxy.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithModel sets the "model" field sent to the sidecar. llama.cpp's
// OpenAI-compatible server accepts (and ignores, for a single-model
// server) any non-empty string here, but Ollama/vLLM deployments may
// route on it, so it is left overridable.
func WithModel(model string) Option {
	return func(c *Client) {
		if model != "" {
			c.model = model
		}
	}
}

// WithTimeout bounds a single HTTP attempt (not the whole call including
// retries — see WithMaxRetries).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxRetries sets how many additional attempts follow a retryable
// failure (connection error or HTTP 5xx). 0 disables retries.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithRetryBackoff sets the base delay between retries. Actual delay
// grows linearly with attempt number (attempt * backoff) — deliberately
// simple, since a local sidecar either comes back in well under a second
// or needs a human, not exponential backoff tuning.
func WithRetryBackoff(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.retryBackoff = d
		}
	}
}

// WithGrammar attaches a GBNF grammar to every request via llama.cpp's
// `grammar` field extension to /v1/chat/completions. The canonical
// grammar text ships at docker/grammar/response.gbnf in this repo; a
// pilot product loads that file (or its own copy of it) and passes its
// contents here. Passing "" (the default) relies entirely on the
// sidecar's own default grammar, which is the server operator's
// responsibility to configure — this client does not embed the grammar
// itself so that the sidecar image remains the single place it is
// versioned.
func WithGrammar(gbnf string) Option {
	return func(c *Client) { c.grammar = gbnf }
}

// WithMaxTokens bounds how many tokens a single response may generate
// (sent as the OpenAI-standard "max_tokens" field). 0 (the zero value
// passed explicitly) is rejected by New in favor of defaultMaxTokens —
// there is no supported way to request unbounded generation, because an
// uncapped response on a slow CPU host can outlast any reasonable
// caller timeout while the grammar is still perfectly satisfied.
func WithMaxTokens(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxTokens = n
		}
	}
}

// WithAPIKey sends "Authorization: Bearer <key>" on every request. Needed
// when the sidecar is not on loopback: a dedicated AI host serving several
// products (Pro/Team tier, started with HEXWARD_AI_API_KEY so llama.cpp
// enforces --api-key), or a BYO OpenAI-compatible endpoint (vLLM, Ollama
// behind a proxy, an internal LLM gateway). An empty key sends no header.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = strings.TrimSpace(key) }
}

// WithDisableThinking asks chat templates that support a reasoning mode
// (Qwen3) to skip it, via the chat_template_kwargs extension understood by
// llama.cpp and vLLM. Narration of one finding does not benefit from a
// hidden reasoning pass, and on CPU it multiplies latency. Leave it off
// for endpoints that reject unknown request fields.
func WithDisableThinking() Option {
	return func(c *Client) { c.noThinking = true }
}

// New creates a Client for the sidecar at baseURL (normally
// DefaultBaseURL). It never fails and never dials — no connection is
// attempted until Explain is called, so constructing a Client when the
// sidecar is absent or disabled is always safe.
func New(baseURL string, opts ...Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		httpClient:   &http.Client{},
		model:        defaultModel,
		timeout:      defaultTimeout,
		maxRetries:   defaultMaxRetries,
		retryBackoff: defaultRetryBackoff,
		maxTokens:    defaultMaxTokens,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// systemPrompt encodes spec §7's grounding rule directly in the request,
// on top of (not instead of) the server-side GBNF grammar: a grammar
// enforces valid JSON shape, it does not stop the model from stating a
// fact that is not in the evidence. Both layers are needed; neither
// replaces the other.
const systemPrompt = `You are the Hexward AI Assist narrator. You will receive one JSON evidence packet describing a single security finding that a Hexward product's own deterministic engine already produced.

Rules you must follow exactly:
1. Use ONLY the fields inside the evidence packet. Do not state any fact (an ID, a rule number, an IP address, a hostname, a CVE identifier, a date, or any other specific value) that is not present in the packet. Do not calculate, convert, round or re-express numbers and dates (no "that is about 11 years"); quote them exactly as the packet gives them. If something relevant is not in the packet, say plainly that the evidence does not contain it.
2. You narrate; you do not decide. Never invent a new finding, never change or imply a different severity, never claim something is fixed, safe, or dangerous beyond what the packet already states.
3. If the feature is hexward.explain_finding: explain in plain language what the finding means, using only its check, title, target, severity, status, remediation and evidence fields, and why it matters to the owner of that target. Keep the explanation to at most four sentences. In what_to_verify give two to four concrete checks a person can actually perform before acting (for example: confirm who owns the target, confirm the change window, re-run the check after the fix) — do not simply restate evidence values as list items. You may restate the packet's own remediation text; never invent a different fix, command, or configuration.
4. If the feature is rulehawk.explain_finding: explain in plain language why the rule relationship in the packet matters, and list what a human should verify before touching the rule. Never draft a replacement rule or CLI command.
5. If the feature is auditlight.why_disappeared: explain, using only the packet's "status" field and its plain meaning (fixed / no_longer_detected / check_failed / target_skipped), which of those happened and what that means for how much the report can be trusted. Never claim "fixed" for any other status value.
6. Respond with a single JSON object matching the required schema exactly: {"explanation": string, "what_to_verify": [string, ...], "disclaimer": string}. No prose outside the JSON object.`

// NormalizeLanguage maps a caller's language hint to the two narration
// languages hexward-ai supports: "id" for Bahasa Indonesia (accepting
// "id", "id-ID", "in", "ind", "indonesian", "bahasa" in any case) and "en"
// for everything else, including the empty string.
func NormalizeLanguage(lang string) string {
	l := strings.ToLower(strings.TrimSpace(lang))
	l = strings.ReplaceAll(l, "_", "-")
	switch {
	case l == "id", l == "in", l == "ind", strings.HasPrefix(l, "id-"),
		l == "indonesian", l == "bahasa", l == "bahasa indonesia":
		return "id"
	default:
		return "en"
	}
}

// languageInstruction is appended to both the system prompt and the end of
// the user turn. Testing on DevNet (24 Sep 2026) showed Phi-4-mini and
// Qwen3-4B answering in English when the only hint was "language":"id"
// inside the JSON packet; an explicit instruction placed last is what
// small models reliably follow.
func languageInstruction(lang string) string {
	if lang == "id" {
		return `Write the "explanation" and every "what_to_verify" item in Bahasa Indonesia. Keep rule text, hostnames, IP addresses, identifiers and other field values exactly as they appear in the packet — do not translate them.`
	}
	return `Write the "explanation" and every "what_to_verify" item in English.`
}

// severityInstruction pins the engine's severity word for the generic
// feature. A live DmarcWatch test (24 Sep 2026) had SmolLM3 call an "info"
// finding "low-severity"; repeating the exact word right before the
// answer is the cheapest reliable guard. Other features return "".
func severityInstruction(evidence EvidencePacket) string {
	sev := findingSeverity(evidence)
	if sev == "" {
		return ""
	}
	return fmt.Sprintf("The engine rated this finding %q. If you mention severity, use exactly that word; never call it higher or lower. ", sev)
}

// findingSeverity returns the engine's severity for generic-feature
// packets, or "" for anything else.
func findingSeverity(evidence EvidencePacket) string {
	if evidence.Feature != FeatureExplainFinding {
		return ""
	}
	var f struct {
		Severity string `json:"severity"`
	}
	if json.Unmarshal(evidence.Finding, &f) != nil {
		return ""
	}
	return strings.TrimSpace(f.Severity)
}

// chatMessage mirrors the OpenAI chat-completions message shape.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatCompletionRequest mirrors the subset of the OpenAI
// /v1/chat/completions request body that hexward-ai needs. Grammar is a
// llama.cpp-specific extension (llama.cpp, Ollama and vLLM all accept
// unknown fields; only llama.cpp currently acts on this one) — see spec
// §4: the contract is "OpenAI-compatible", not "only OpenAI's own API",
// specifically so this field can be used.
type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	Grammar     string        `json:"grammar,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	// ChatTemplateKwargs is a llama.cpp/vLLM extension; only sent when
	// WithDisableThinking is set.
	ChatTemplateKwargs map[string]any `json:"chat_template_kwargs,omitempty"`
}

// chatCompletionResponse mirrors the subset of the OpenAI response shape
// this client reads. Error is populated by some OpenAI-compatible
// servers (including llama.cpp) instead of an HTTP error status for
// certain failure modes (e.g. context length exceeded).
type chatCompletionResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Explain sends one EvidencePacket to hexward-ai and returns its
// grammar-constrained narration. It is the single entry point for both
// Phase 1 pilot features (spec §9) — callers select behavior with
// evidence.Feature, not with a different method per feature, so adding
// a Phase 2 feature never breaks this signature.
//
// Explain never returns a response with an empty or model-authored
// Disclaimer: that field is always overwritten with CanonicalDisclaimer
// before returning, so a caller can render exp.Disclaimer directly and
// know it is exactly the sentence spec §7 requires, verbatim, regardless
// of what the model produced.
func (c *Client) Explain(ctx context.Context, evidence EvidencePacket) (*Explanation, error) {
	if evidence.Feature == "" {
		return nil, fmt.Errorf("aiclient: EvidencePacket.Feature is required")
	}
	if evidence.Product == "" {
		return nil, fmt.Errorf("aiclient: EvidencePacket.Product is required")
	}
	if len(evidence.Finding) == 0 {
		return nil, fmt.Errorf("aiclient: EvidencePacket.Finding is required")
	}

	evidence.Language = NormalizeLanguage(evidence.Language)
	payload, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("aiclient: marshal evidence packet: %w", err)
	}

	reqBody := chatCompletionRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt + "\n7. " + languageInstruction(evidence.Language)},
			{Role: "user", Content: string(payload) + "\n\n" + severityInstruction(evidence) + languageInstruction(evidence.Language)},
		},
		// Low, not zero: some llama.cpp builds treat temperature 0 as
		// "unset" and fall back to a sampler default. Low temperature
		// keeps narration close to the evidence, matching the
		// grounding rule above.
		Temperature: 0.2,
		Grammar:     c.grammar,
		MaxTokens:   c.maxTokens,
	}
	if c.noThinking {
		reqBody.ChatTemplateKwargs = map[string]any{"enable_thinking": false}
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * c.retryBackoff):
			}
		}

		exp, err := c.doRequest(ctx, reqBody)
		if err == nil {
			if sev := findingSeverity(evidence); sev != "" {
				exp.ExplanationText = dropConflictingSeverity(exp.ExplanationText, sev)
			}
			exp.Disclaimer = CanonicalDisclaimer
			return exp, nil
		}
		lastErr = err
		if !isRetryable(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w (after %d attempt(s)): %v", ErrUnavailable, c.maxRetries+1, lastErr)
}

// retryableError marks an error from doRequest as safe to retry: a
// transport-level failure (connection refused, DNS, timeout) or an HTTP
// 5xx. HTTP 4xx and JSON-parse failures are never wrapped in this type,
// because retrying an identical malformed request produces the identical
// malformed response.
type retryableError struct{ err error }

func (r *retryableError) Error() string { return r.err.Error() }
func (r *retryableError) Unwrap() error { return r.err }

func isRetryable(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}

func (c *Client) doRequest(ctx context.Context, reqBody chatCompletionRequest) (*Explanation, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("aiclient: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("aiclient: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Connection refused, DNS failure, TLS failure, timeout — the
		// sidecar is not answering at all. Always retryable.
		return nil, &retryableError{fmt.Errorf("aiclient: request to %s: %w", c.baseURL, err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap: this is narration, not a document
	if err != nil {
		return nil, &retryableError{fmt.Errorf("aiclient: read response body: %w", err)}
	}

	if resp.StatusCode >= 500 {
		return nil, &retryableError{fmt.Errorf("%w: HTTP %d: %s", ErrUnavailable, resp.StatusCode, truncate(respBody, 300))}
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrInvalidRequest, resp.StatusCode, truncate(respBody, 300))
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %s", ErrInvalidResponse, truncate(respBody, 300))
	}
	if parsed.Error != nil {
		// Some OpenAI-compatible servers answer 200 with an error body.
		return nil, &retryableError{fmt.Errorf("%w: sidecar reported an error: %s", ErrUnavailable, parsed.Error.Message)}
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("%w: response had no choices", ErrInvalidResponse)
	}

	content := parsed.Choices[0].Message.Content
	var exp Explanation
	if err := json.Unmarshal([]byte(content), &exp); err != nil {
		return nil, fmt.Errorf("%w: model content was not the required JSON schema: %s", ErrInvalidResponse, truncate([]byte(content), 300))
	}
	if strings.TrimSpace(exp.ExplanationText) == "" {
		return nil, fmt.Errorf("%w: empty explanation field", ErrInvalidResponse)
	}

	return &exp, nil
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
