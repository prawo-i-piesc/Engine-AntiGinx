package HttpClient

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"time"
)

type httpError struct {
	url     string
	code    int
	message string
	error   any
}

// Customizable HTTP wrapper configuration
type httpWrapperConfig struct {
	headers          map[string]string
	antiBotDetection bool
}

type WrapperOption func(*httpWrapperConfig)

func defaultHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "AntiGinx/1.0",
	}
}

// getAntiDetectionHeaders returns realistic browser headers to avoid bot detection
func getAntiDetectionHeaders() map[string]string {
	return map[string]string{
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language":           "en-US,en;q=0.9,pl;q=0.8",
		"Accept-Encoding":           "gzip, deflate, br",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"Cache-Control":             "max-age=0",
		"Pragma":                    "no-cache",
		"Sec-GPC":                   "1",
	}
}

// getAdvancedStealthHeaders provides maximum stealth with all browser characteristics
func getAdvancedStealthHeaders() map[string]string {
	headers := getAntiDetectionHeaders()

	// Enhanced client hints (matching real Chrome browser)
	headers["sec-ch-viewport-width"] = "1920"
	headers["sec-ch-viewport-height"] = "1080"
	headers["sec-ch-dpr"] = "1"
	headers["sec-ch-device-memory"] = "8"
	headers["sec-ch-ua-arch"] = `"x86"`
	headers["sec-ch-ua-bitness"] = `"64"`
	headers["sec-ch-ua-full-version"] = `"120.0.6099.109"`
	headers["sec-ch-ua-model"] = `""`
	headers["sec-ch-ua-platform-version"] = `"15.0.0"`
	headers["sec-ch-ua-wow64"] = "?0"

	// Additional stealth headers
	headers["sec-ch-prefers-color-scheme"] = "light"
	headers["sec-ch-prefers-reduced-motion"] = "no-preference"
	headers["Viewport-Width"] = "1920"
	headers["Width"] = "1920"

	// Browser feature detection headers
	headers["Save-Data"] = "0"
	headers["Device-Memory"] = "8"
	headers["RTT"] = "100"
	headers["Downlink"] = "10"
	headers["ECT"] = "4g"

	return headers
}

// getRandomUserAgent returns a random realistic user agent
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

// getBrowserTLSConfig returns TLS configuration that mimics real browsers
func getBrowserTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func WithHeaders(h map[string]string) WrapperOption {
	return func(cfg *httpWrapperConfig) {
		for k, v := range h {
			cfg.headers[k] = v // override or add new key
		}
	}
}

// WithAntiBotDetection enables comprehensive anti-bot detection bypass with all available techniques
func WithAntiBotDetection(level string) WrapperOption {
	return func(cfg *httpWrapperConfig) {
		cfg.antiBotDetection = true

		// Set appropriate headers based on protection level
		var headers map[string]string
		switch level {
		case "basic":
			headers = getAntiDetectionHeaders()
		case "advanced", "maximum", "stealth":
			headers = getAdvancedStealthHeaders()
		default:
			headers = getAntiDetectionHeaders()
		}

		// Apply headers
		for k, v := range headers {
			if _, exists := cfg.headers[k]; !exists {
				cfg.headers[k] = v
			}
		}
	}
}

// HTTP wrapper struct

type httpWrapper struct {
	client *http.Client
	config httpWrapperConfig
}

func CreateHttpWrapper(opts ...WrapperOption) *httpWrapper {
	cfg := httpWrapperConfig{
		headers:          defaultHeaders(),
		antiBotDetection: false,
	}

	// apply optional config
	for _, opt := range opts {
		opt(&cfg)
	}

	// Create transport with advanced configuration
	transport := &http.Transport{}

	// Configure TLS and other settings if anti-bot detection is enabled
	if cfg.antiBotDetection {
		transport.TLSClientConfig = getBrowserTLSConfig()

		// Configure for HTTP/2 support like real browsers
		transport.ForceAttemptHTTP2 = true
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 10
		transport.IdleConnTimeout = 90 * time.Second
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Add cookie jar if anti-bot detection is enabled
	if cfg.antiBotDetection {
		if jar, err := cookiejar.New(nil); err == nil {
			client.Jar = jar
		}
	}

	return &httpWrapper{
		client: client,
		config: cfg,
	}
}

func (hw *httpWrapper) Get(url string, opts ...WrapperOption) *http.Response {
	// Start with wrapper's base config
	cfg := hw.config

	// Apply per-call overrides
	for _, opt := range opts {
		opt(&cfg)
	}

	// Apply request delay for human-like behavior if anti-bot detection is enabled
	if cfg.antiBotDetection {
		delay := time.Duration(rand.Intn(2000)+1000) * time.Millisecond // 1-3 second delay
		time.Sleep(delay)
	}

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(httpError{
			url:     url,
			code:    100,
			message: "Failed to create HTTP request: " + err.Error(),
			error:   err,
		})
	}

	// Use random user agent if anti-bot detection is enabled
	headers := hw.config.headers
	if cfg.antiBotDetection {
		headers = make(map[string]string)
		for k, v := range hw.config.headers {
			headers[k] = v
		}
		headers["User-Agent"] = getRandomUserAgent()
	}

	// Add headers in browser-like order only if anti-bot detection is enabled
	if cfg.antiBotDetection {
		browserHeaderOrder := []string{
			"Host",
			"Connection",
			"Cache-Control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"Upgrade-Insecure-Requests",
			"User-Agent",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-User",
			"Sec-Fetch-Dest",
			"Accept-Encoding",
			"Accept-Language",
		}

		// Set headers in realistic browser order
		for _, headerName := range browserHeaderOrder {
			if value, exists := headers[headerName]; exists {
				req.Header.Set(headerName, value)
			}
		}

		// Add any remaining headers
		for key, value := range headers {
			if req.Header.Get(key) == "" {
				req.Header.Set(key, value)
			}
		}
	} else {
		// Simple header addition when anti-bot detection is disabled
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Set Host header explicitly (browsers do this)
	if req.URL.Host != "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// Execute the request
	resp, err := hw.client.Do(req)

	// Network error
	if err != nil {
		panic(httpError{
			url:  url,
			code: 101,
			message: `Network error occurred. This could be due to:
				- DNS lookup failures
				- Connection timeouts
				- Network unreachable
				- No response object exists (resp == nil)`,
			error: err,
		})
	}

	defer resp.Body.Close()

	// Handle HTTP error status codes
	if resp.StatusCode != 200 {
		panic(httpError{
			url:     url,
			code:    102,
			message: "HTTP Status code not 200 (OK): " + strconv.Itoa(resp.StatusCode),
			error:   resp,
		})
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(httpError{
			url:     url,
			code:    200,
			message: "Error reading response body: " + err.Error(),
			error:   err,
		})
	}

	// Enhanced bot protection detection
	bodyStr := string(body)
	var detectedProtections []string

	// Check for Cloudflare headers and challenges
	if resp.Header.Get("Server") == "cloudflare" {
		detectedProtections = append(detectedProtections, "Cloudflare Server")
	}
	if resp.Header.Get("CF-RAY") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Ray ID: "+resp.Header.Get("CF-RAY"))
	}
	if resp.Header.Get("CF-Cache-Status") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Cache: "+resp.Header.Get("CF-Cache-Status"))
	}
	if resp.Header.Get("CF-CHL-BCODE") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Challenge")
	}

	// Check for various bot protection services
	protectionIndicators := map[string]string{
		"cf-browser-verification": "Cloudflare Browser Verification",
		"__cf_bm":                 "Cloudflare Bot Management",
		"incapsula":               "Incapsula Protection",
		"distil":                  "Distil Networks",
		"perimeterx":              "PerimeterX",
		"datadome":                "DataDome",
		"reblaze":                 "Reblaze",
		"radware":                 "Radware",
	}

	for indicator, service := range protectionIndicators {
		if helpers.ContainsAny(bodyStr, []string{indicator}) {
			detectedProtections = append(detectedProtections, service+" detected")
		}
	}

	// Enhanced content-based detection
	challengeKeywords := []string{
		"cloudflare", "captcha", "Attention Required", "challenge",
		"verify you are human", "security check", "DDoS protection",
		"Access denied", "blocked", "suspicious activity",
		"bot detected", "automated traffic", "rate limited",
		"javascript is required", "browser check",
	}

	for _, keyword := range challengeKeywords {
		if helpers.ContainsAny(bodyStr, []string{keyword}) {
			detectedProtections = append(detectedProtections, "Content contains: "+keyword)
		}
	}

	// Only panic if not using anti-bot detection (in strict mode)
	if len(detectedProtections) > 0 && !cfg.antiBotDetection {
		detectionMsg := "Bot protection detected:\n"
		for i, detection := range detectedProtections {
			detectionMsg += fmt.Sprintf("  %d. %s\n", i+1, detection)
		}

		panic(httpError{
			url:     url,
			code:    300,
			message: detectionMsg,
			error:   resp,
		})
	}

	return resp
}
