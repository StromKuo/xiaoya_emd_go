package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultStrmSignEndpoint  = "http://xiaoya/api/getsignmd5"
	strmSignCacheTTL         = 10 * time.Minute
	strmSignStaleGrace       = 30 * time.Minute
	strmSignRetryBackoff     = 30 * time.Second
	strmSignRequestTimeout   = 10 * time.Second
	strmSignMonitorInterval  = 10 * time.Minute
	maxStrmPendingRetryPaths = 10000
	strmSignCommand          = "cat md5"
	strmSignEndpointEnv      = "XIAOYA_STRM_SIGN_ENDPOINT"
	strmSignTokenFileEnv     = "XIAOYA_STRM_TOKEN_FILE"
)

var md5SignPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

var errStrmSignFetch = errors.New("STRM 签名获取失败")
var errStrmConfigChanged = errors.New("STRM 配置已变化")

// SignCache caches the current Xiaoya sign and serializes refreshes so a
// concurrent sync only sends one request to the sign endpoint.
type SignCache struct {
	mu               sync.Mutex
	client           *http.Client
	ttl              time.Duration
	staleGrace       time.Duration
	sign             string
	endpoint         string
	tokenFingerprint [sha256.Size]byte
	expiresAt        time.Time
	staleUntil       time.Time
	retryAfter       time.Time
	failureEndpoint  string
	failureToken     [sha256.Size]byte
	failureRetryAt   time.Time
}

func newSignCache() *SignCache {
	return &SignCache{
		client:     newDirectSignHTTPClient(),
		ttl:        strmSignCacheTTL,
		staleGrace: strmSignStaleGrace,
	}
}

func newDirectSignHTTPClient() *http.Client {
	transport := &http.Transport{}
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	}
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   strmSignRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var strmSignCache = newSignCache()

var (
	strmSignMonitorOnce    sync.Once
	strmSignMonitorTrigger = make(chan struct{}, 1)
	strmSignMonitorRetryMu sync.Mutex
	strmSignMonitorRetryAt time.Time
)

// Get returns the cached sign, or refreshes it. refreshed is true only for
// the goroutine that performed the HTTP request. usedStale is true when a
// failed refresh was covered by the short stale-sign grace period.
func (c *SignCache) Get(ctx context.Context, endpoint, token string) (sign string, refreshed, usedStale bool, err error) {
	sign, refreshed, _, usedStale, err = c.GetWithChange(ctx, endpoint, token)
	return sign, refreshed, usedStale, err
}

func (c *SignCache) GetWithChange(ctx context.Context, endpoint, token string) (sign string, refreshed, changed, usedStale bool, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", false, false, false, fmt.Errorf("签名接口地址不能为空")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false, false, false, fmt.Errorf("小雅签名 token 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tokenFingerprint := sha256.Sum256([]byte(token))

	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.sign != "" && c.endpoint == endpoint && c.tokenFingerprint == tokenFingerprint && now.Before(c.expiresAt) {
		return c.sign, false, false, false, nil
	}
	if c.sign != "" && c.endpoint == endpoint && c.tokenFingerprint == tokenFingerprint && now.Before(c.retryAfter) && now.Before(c.staleUntil) {
		return c.sign, false, false, true, nil
	}
	if c.failureEndpoint == endpoint && c.failureToken == tokenFingerprint && now.Before(c.failureRetryAt) {
		return "", false, false, false, errStrmSignFetch
	}

	previousSign := c.sign
	client := c.client
	if client == nil {
		client = newDirectSignHTTPClient()
	}
	requestCtx, cancel := context.WithTimeout(ctx, strmSignRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(strmSignCommand))
	if err != nil {
		staleSign, staleRefreshed, staleUsed, staleErr := c.staleOrError(endpoint, tokenFingerprint, fmt.Errorf("创建签名请求失败"))
		return staleSign, staleRefreshed, false, staleUsed, staleErr
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "text/plain")
	// The endpoint executes the submitted command. Keep this command fixed;
	// it must never come from configuration or an HTTP request body.
	resp, err := client.Do(req)
	if err != nil {
		staleSign, staleRefreshed, staleUsed, staleErr := c.staleOrError(endpoint, tokenFingerprint, fmt.Errorf("请求签名接口失败"))
		return staleSign, staleRefreshed, false, staleUsed, staleErr
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		staleSign, staleRefreshed, staleUsed, staleErr := c.staleOrError(endpoint, tokenFingerprint, fmt.Errorf("签名接口返回 HTTP %d", resp.StatusCode))
		return staleSign, staleRefreshed, false, staleUsed, staleErr
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		staleSign, staleRefreshed, staleUsed, staleErr := c.staleOrError(endpoint, tokenFingerprint, fmt.Errorf("读取签名接口响应失败"))
		return staleSign, staleRefreshed, false, staleUsed, staleErr
	}
	sign = strings.TrimSpace(string(body))
	if !md5SignPattern.MatchString(sign) {
		staleSign, staleRefreshed, staleUsed, staleErr := c.staleOrError(endpoint, tokenFingerprint, fmt.Errorf("签名接口返回的 sign 不是有效的 MD5"))
		return staleSign, staleRefreshed, false, staleUsed, staleErr
	}

	c.sign = sign
	c.endpoint = endpoint
	c.tokenFingerprint = tokenFingerprint
	c.expiresAt = now.Add(c.ttl)
	c.staleUntil = c.expiresAt.Add(c.staleGrace)
	c.retryAfter = time.Time{}
	c.failureEndpoint = ""
	c.failureToken = [sha256.Size]byte{}
	c.failureRetryAt = time.Time{}
	return sign, true, previousSign != sign, false, nil
}

func (c *SignCache) staleOrError(endpoint string, tokenFingerprint [sha256.Size]byte, err error) (string, bool, bool, error) {
	c.failureEndpoint = endpoint
	c.failureToken = tokenFingerprint
	c.failureRetryAt = time.Now().Add(strmSignRetryBackoff)
	if c.sign != "" && c.endpoint == endpoint && c.tokenFingerprint == tokenFingerprint && time.Now().Before(c.staleUntil) {
		c.retryAfter = time.Now().Add(strmSignRetryBackoff)
		return c.sign, false, true, nil
	}
	return "", false, false, fmt.Errorf("%w：%v", errStrmSignFetch, err)
}

func (c *SignCache) Invalidate() {
	c.mu.Lock()
	c.sign = ""
	c.endpoint = ""
	c.tokenFingerprint = [sha256.Size]byte{}
	c.expiresAt = time.Time{}
	c.staleUntil = time.Time{}
	c.retryAfter = time.Time{}
	c.failureEndpoint = ""
	c.failureToken = [sha256.Size]byte{}
	c.failureRetryAt = time.Time{}
	c.mu.Unlock()
}

// strmSyncGate prevents an existing-file repair from racing with a normal
// STRM download. NFO, image and other non-STRM downloads do not use it.
var strmSyncGate sync.RWMutex

// normalizeHTTPURL validates a URL used by the STRM feature without ever
// logging its value. Userinfo is rejected so credentials cannot be stored in
// configuration accidentally.
func normalizeHTTPURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("地址不能为空")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("必须是合法的 http 或 https URL")
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("协议必须为 http 或 https")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("URL 不允许包含用户名或密码")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	return parsed, nil
}

func normalizeStrmBaseURL(raw string) (string, error) {
	parsed, err := normalizeHTTPURL(raw)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("STRM 基础地址不能包含查询参数或 fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.RawPath != "" {
		parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	}
	return parsed.String(), nil
}

func normalizeStrmSignEndpoint(raw string) (string, error) {
	parsed, err := normalizeHTTPURL(raw)
	if err != nil {
		return "", err
	}
	if parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Path != "/api/getsignmd5" {
		return "", fmt.Errorf("签名接口地址必须为 /api/getsignmd5，且不能包含查询参数或 fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !isTrustedStrmSignHost(host) {
		return "", fmt.Errorf("签名接口主机必须是小雅内部服务名、localhost、回环地址或私有网段地址")
	}
	return parsed.String(), nil
}

func resolveStrmSignToken(configToken string) (string, error) {
	if tokenFile := strings.TrimSpace(os.Getenv(strmSignTokenFileEnv)); tokenFile != "" {
		body, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("读取小雅签名 token 文件失败")
		}
		if token := strings.TrimSpace(string(body)); token != "" {
			return token, nil
		}
		return "", fmt.Errorf("小雅签名 token 文件为空")
	}
	if token := strings.TrimSpace(configToken); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("小雅签名 token 不能为空")
}

func configuredStrmSignEndpoint(value string) string {
	if endpoint := strings.TrimSpace(os.Getenv(strmSignEndpointEnv)); endpoint != "" {
		return endpoint
	}
	return value
}

func isTrustedStrmSignHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "xiaoya" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func validateStrmConfig(enabled bool, baseURL, signEndpoint string) (normalizedBaseURL, normalizedEndpoint string, err error) {
	normalizedEndpoint, err = normalizeStrmSignEndpoint(signEndpoint)
	if err != nil {
		return "", "", fmt.Errorf("签名接口地址无效：%v", err)
	}
	if strings.TrimSpace(baseURL) == "" {
		if enabled {
			return "", "", fmt.Errorf("启用 STRM 重写时基础地址不能为空")
		}
		return "", normalizedEndpoint, nil
	}
	normalizedBaseURL, err = normalizeStrmBaseURL(baseURL)
	if err != nil {
		return "", "", fmt.Errorf("STRM 基础地址无效：%v", err)
	}
	return normalizedBaseURL, normalizedEndpoint, nil
}

// normalizeStrmSourceHost canonicalizes a configured source host. A host-only
// rule matches any port; a host:port rule matches that exact port.
func normalizeStrmSourceHost(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", fmt.Errorf("来源主机不能为空")
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@") {
		return "", "", fmt.Errorf("来源主机不能包含协议、路径、查询参数或用户信息")
	}
	parseValue := value
	if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
		parseValue = "[" + value + "]"
	}
	parsed, err := url.Parse("http://" + parseValue)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", "", fmt.Errorf("来源主机格式无效")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", "", fmt.Errorf("来源主机不能为空")
	}
	port := parsed.Port()
	if port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", "", fmt.Errorf("来源主机端口无效")
		}
		port = strconv.Itoa(portNumber)
	}
	return host, port, nil
}

func normalizeStrmSourceHosts(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		host, port, err := normalizeStrmSourceHost(item)
		if err != nil {
			return nil, fmt.Errorf("来源主机 %q 无效：%v", strings.TrimSpace(item), err)
		}
		canonical := host
		if port != "" {
			canonical = net.JoinHostPort(host, port)
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func strmSourceHostAllowed(source *url.URL, allowed []string) bool {
	if source == nil || len(allowed) == 0 {
		return len(allowed) == 0
	}
	sourceHost := strings.ToLower(source.Hostname())
	sourcePort := strmURLPort(source)
	for _, item := range allowed {
		host, port, err := normalizeStrmSourceHost(item)
		if err != nil || host != sourceHost {
			continue
		}
		if port == "" || port == sourcePort {
			return true
		}
	}
	return false
}

func strmURLPort(value *url.URL) string {
	if value == nil {
		return ""
	}
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func strmSourceOrTargetHostAllowed(source *url.URL, allowed []string, target *url.URL) bool {
	if strmSourceHostAllowed(source, allowed) {
		return true
	}
	if source == nil || target == nil {
		return false
	}
	return strings.EqualFold(source.Hostname(), target.Hostname()) && strmURLPort(source) == strmURLPort(target)
}

func applyStrmConfigDefaults(cfg *Config) error {
	cfg.StrmSignEndpoint = configuredStrmSignEndpoint(cfg.StrmSignEndpoint)
	if strings.TrimSpace(cfg.StrmSignEndpoint) == "" {
		cfg.StrmSignEndpoint = defaultStrmSignEndpoint
	}
	baseURL, endpoint, err := validateStrmConfig(cfg.StrmRewriteEnabled, cfg.StrmBaseURL, cfg.StrmSignEndpoint)
	if err != nil {
		return err
	}
	cfg.StrmBaseURL = baseURL
	cfg.StrmSignEndpoint = endpoint
	normalizedHosts, err := normalizeStrmSourceHosts(cfg.StrmSourceHosts)
	if err != nil {
		return err
	}
	if cfg.StrmRewriteEnabled {
		if _, err := resolveStrmSignToken(cfg.StrmSignToken); err != nil {
			return fmt.Errorf("启用 STRM 重写时小雅签名 token 不能为空")
		}
		if len(normalizedHosts) == 0 {
			return fmt.Errorf("启用 STRM 重写时至少需要配置一个来源主机")
		}
	}
	cfg.StrmSignToken = strings.TrimSpace(cfg.StrmSignToken)
	cfg.StrmSourceHosts = normalizedHosts
	return nil
}

func joinURLPath(basePath, childPath string) string {
	if basePath == "" || basePath == "/" {
		if strings.HasPrefix(childPath, "/") {
			return childPath
		}
		return "/" + childPath
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(childPath, "/")
}

func parseStrmURL(content []byte) (*url.URL, bool, error) {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, false, fmt.Errorf("STRM 文件为空")
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return nil, false, fmt.Errorf("STRM 文件必须只包含一个 URL")
	}
	source, err := url.Parse(trimmed)
	if err != nil {
		return nil, false, fmt.Errorf("STRM URL 解析失败")
	}
	if source.Scheme == "" {
		return nil, false, fmt.Errorf("STRM 内容不是有效 URL")
	}
	if !strings.EqualFold(source.Scheme, "http") && !strings.EqualFold(source.Scheme, "https") {
		return source, false, nil
	}
	if source.Host == "" || source.Opaque != "" {
		return nil, false, fmt.Errorf("STRM URL 解析失败")
	}
	return source, strings.HasPrefix(source.Path, "/d/"), nil
}

// rewriteSTRMContent rewrites only Xiaoya /d/ URLs. Unsupported protocols
// and non-/d/ URLs are deliberately returned unchanged and marked skipped.
func rewriteSTRMContent(content []byte, baseURL, sign string) ([]byte, bool, error) {
	return rewriteSTRMContentWithHosts(content, baseURL, sign, nil)
}

func rewriteSTRMContentWithHosts(content []byte, baseURL, sign string, sourceHosts []string) ([]byte, bool, error) {
	source, needsRewrite, err := parseStrmURL(content)
	if err != nil {
		return nil, false, err
	}
	if !needsRewrite {
		return content, false, nil
	}
	normalizedBaseURL, err := normalizeStrmBaseURL(baseURL)
	if err != nil {
		return nil, false, err
	}
	base, err := url.Parse(normalizedBaseURL)
	if err != nil {
		return nil, false, fmt.Errorf("STRM 基础地址解析失败")
	}
	if !strmSourceOrTargetHostAllowed(source, sourceHosts, base) {
		return content, false, nil
	}
	if !md5SignPattern.MatchString(sign) {
		return nil, false, fmt.Errorf("sign 不是有效的 MD5")
	}
	target := *base
	target.Path = joinURLPath(base.Path, source.Path)
	baseEscapedPath := base.EscapedPath()
	sourceEscapedPath := source.EscapedPath()
	target.RawPath = joinURLPath(baseEscapedPath, sourceEscapedPath)
	if target.RawPath == target.Path {
		target.RawPath = ""
	}
	query := source.Query()
	query.Del("sign")
	query.Set("sign", sign)
	target.RawQuery = query.Encode()
	target.Fragment = ""
	target.ForceQuery = false
	output := target.String() + "\n"
	if string(content) == output {
		return content, false, nil
	}
	return []byte(output), true, nil
}

func rewriteDownloadedSTRM(ctx context.Context, path, baseURL, signEndpoint, signToken string, sourceHosts []string) (refreshed bool, usedStale bool, err error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, false, fmt.Errorf("读取 STRM 临时文件失败")
	}
	source, needsRewrite, err := parseStrmURL(content)
	if err != nil {
		return false, false, err
	}
	baseURLValue, err := normalizeStrmBaseURL(baseURL)
	if err != nil {
		return false, false, err
	}
	base, err := url.Parse(baseURLValue)
	if err != nil {
		return false, false, fmt.Errorf("STRM 基础地址解析失败")
	}
	if !needsRewrite || !strmSourceOrTargetHostAllowed(source, sourceHosts, base) {
		return false, false, nil
	}
	resolvedToken, err := resolveStrmSignToken(signToken)
	if err != nil {
		return false, false, fmt.Errorf("%w：%v", errStrmSignFetch, err)
	}
	sign, refreshed, usedStale, err := strmSignCache.Get(ctx, signEndpoint, resolvedToken)
	if err != nil {
		return false, false, fmt.Errorf("%w：%v", errStrmSignFetch, err)
	}
	_, err = rewriteSTRMFileWithHosts(path, baseURL, sign, sourceHosts)
	return refreshed, usedStale, err
}

func rewriteSTRMFile(path, baseURL, sign string) (bool, error) {
	return rewriteSTRMFileWithHosts(path, baseURL, sign, nil)
}

func rewriteSTRMFileWithHosts(path, baseURL, sign string, sourceHosts []string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("读取 STRM 临时文件失败")
	}
	rewritten, changed, err := rewriteSTRMContentWithHosts(content, baseURL, sign, sourceHosts)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if err := os.WriteFile(path, rewritten, 0600); err != nil {
		return false, fmt.Errorf("写入 STRM 临时文件失败")
	}
	return true, nil
}

// rewriteSTRMFileAtomic updates an existing STRM through a same-directory
// temporary file and keeps its original modification time before rename.
func rewriteSTRMFileAtomic(path, baseURL, sign string) (bool, error) {
	return rewriteSTRMFileAtomicWithHosts(path, baseURL, sign, nil)
}

func rewriteSTRMFileAtomicWithHosts(path, baseURL, sign string, sourceHosts []string) (bool, error) {
	if !strings.EqualFold(filepath.Ext(path), ".strm") {
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("读取 STRM 文件信息失败")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("读取 STRM 文件失败")
	}
	rewritten, changed, err := rewriteSTRMContentWithHosts(content, baseURL, sign, sourceHosts)
	if err != nil || !changed {
		return false, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".rewrite-*")
	if err != nil {
		return false, fmt.Errorf("创建 STRM 临时文件失败")
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("设置 STRM 临时文件权限失败")
	}
	if _, err := tmp.Write(rewritten); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("写入 STRM 临时文件失败")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("同步 STRM 临时文件失败")
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("关闭 STRM 临时文件失败")
	}
	if err := os.Chtimes(tmpPath, info.ModTime(), info.ModTime()); err != nil {
		return false, fmt.Errorf("保留 STRM 文件时间失败")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("原子替换 STRM 文件失败")
	}
	removeTemp = false
	return true, nil
}

func isStrmRewriteTempFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(name, ".") && strings.Contains(name, ".strm.rewrite-")
}

// StrmRewriteStatus describes the explicitly started historical repair task.
type StrmRewriteStatus struct {
	Running              bool      `json:"running"`
	Scanned              int       `json:"scanned"`
	Updated              int       `json:"updated"`
	Skipped              int       `json:"skipped"`
	Failed               int       `json:"failed"`
	PendingRetryCount    int       `json:"pendingRetryCount"`
	PendingRetryOverflow bool      `json:"pendingRetryOverflow"`
	LastError            string    `json:"lastError,omitempty"`
	StartedAt            time.Time `json:"startedAt,omitempty"`
	FinishedAt           time.Time `json:"finishedAt,omitempty"`
}

var (
	strmRewriteStatus   StrmRewriteStatus
	strmRewriteStatusMu sync.Mutex
)

func getStrmRewriteStatus() StrmRewriteStatus {
	strmRewriteStatusMu.Lock()
	status := strmRewriteStatus
	strmRewriteStatusMu.Unlock()

	configMu.RLock()
	status.PendingRetryCount = len(config.StrmPendingRetryPaths)
	status.PendingRetryOverflow = config.StrmPendingRetryOverflow
	configMu.RUnlock()
	return status
}

func startStrmRewrite(mediaDir, baseURL, signEndpoint, signToken string, sourceHosts []string) bool {
	return startStrmRewriteAtGeneration(mediaDir, baseURL, signEndpoint, signToken, sourceHosts, currentStrmConfigGeneration())
}

func startStrmRewriteAtGeneration(mediaDir, baseURL, signEndpoint, signToken string, sourceHosts []string, generation uint64) bool {
	return startStrmRewriteJob(func() {
		runStrmRewriteAtGeneration(mediaDir, baseURL, signEndpoint, signToken, sourceHosts, generation)
	})
}

func startStrmRewriteWithSign(mediaDir, baseURL, sign string, sourceHosts []string, onSuccess func() error) bool {
	return startStrmRewriteWithSignAtGeneration(mediaDir, baseURL, sign, sourceHosts, currentStrmConfigGeneration(), onSuccess)
}

func startStrmRewriteWithSignAtGeneration(mediaDir, baseURL, sign string, sourceHosts []string, generation uint64, onSuccess func() error) bool {
	return startStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, nil, generation, func(_ StrmRewriteResult) error {
		if onSuccess == nil {
			return nil
		}
		return onSuccess()
	})
}

func startStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign string, sourceHosts, retryPaths []string, generation uint64, onSuccess func(StrmRewriteResult) error) bool {
	return startStrmRewriteJob(func() {
		if generation != 0 && !strmConfigGenerationMatches(generation) {
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.LastError = "STRM 配置已变化，取消历史修复"
			})
			return
		}
		result := runStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, retryPaths, generation)
		if !result.Completed || onSuccess == nil {
			if !result.Completed {
				delayStrmSignMonitorRetry(strmSignRetryBackoff)
			}
			return
		}
		if err := onSuccess(result); err != nil {
			delayStrmSignMonitorRetry(strmSignRetryBackoff)
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Failed++
				status.LastError = "保存 STRM 签名应用状态失败"
			})
		} else if len(result.RetryPaths) > 0 {
			delayStrmSignMonitorRetry(strmSignMonitorInterval)
		} else {
			resetStrmSignMonitorRetry()
		}
	})
}

func startStrmRewriteJob(job func()) bool {
	strmRewriteStatusMu.Lock()
	if strmRewriteStatus.Running {
		strmRewriteStatusMu.Unlock()
		return false
	}
	strmRewriteStatus = StrmRewriteStatus{
		Running:   true,
		StartedAt: time.Now(),
	}
	strmRewriteStatusMu.Unlock()

	go func() {
		defer func() {
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Running = false
				status.FinishedAt = time.Now()
			})
			requestStrmSignMonitor()
		}()
		job()
	}()
	return true
}

func updateStrmRewriteStatus(update func(*StrmRewriteStatus)) {
	strmRewriteStatusMu.Lock()
	update(&strmRewriteStatus)
	strmRewriteStatusMu.Unlock()
}

func runStrmRewrite(mediaDir, baseURL, signEndpoint, signToken string, sourceHosts []string) {
	runStrmRewriteAtGeneration(mediaDir, baseURL, signEndpoint, signToken, sourceHosts, 0)
}

func runStrmRewriteAtGeneration(mediaDir, baseURL, signEndpoint, signToken string, sourceHosts []string, generation uint64) {
	if generation != 0 && !strmConfigGenerationMatches(generation) {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "STRM 配置已变化，取消历史修复"
		})
		return
	}
	if _, err := normalizeStrmSignEndpoint(signEndpoint); err != nil {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "签名接口地址无效"
		})
		return
	}
	resolvedToken, err := resolveStrmSignToken(signToken)
	if err != nil {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "小雅签名 token 未配置"
		})
		return
	}
	sign, _, _, usedStale, err := strmSignCache.GetWithChange(context.Background(), signEndpoint, resolvedToken)
	if err != nil {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "获取 STRM 签名失败"
		})
		return
	}
	if usedStale {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "签名刷新失败，使用短期缓存"
		})
	}
	result := runStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, nil, generation)
	if !result.Completed {
		delayStrmSignMonitorRetry(strmSignRetryBackoff)
		return
	}
	if !usedStale {
		if err := persistStrmAppliedState(sign, baseURL, signEndpoint, resolvedToken, sourceHosts, result.RetryPaths, result.RetryOverflow); err != nil {
			delayStrmSignMonitorRetry(strmSignRetryBackoff)
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Failed++
				status.LastError = "保存 STRM 签名应用状态失败"
			})
		} else if len(result.RetryPaths) > 0 {
			delayStrmSignMonitorRetry(strmSignMonitorInterval)
		} else {
			resetStrmSignMonitorRetry()
		}
	}
}

func runStrmRewriteWithSign(mediaDir, baseURL, sign string, sourceHosts []string) bool {
	return runStrmRewriteWithSignAtGeneration(mediaDir, baseURL, sign, sourceHosts, 0)
}

func runStrmRewriteWithSignAtGeneration(mediaDir, baseURL, sign string, sourceHosts []string, generation uint64) bool {
	return runStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, nil, generation).Completed
}

type StrmRewriteResult struct {
	Completed     bool
	RetryPaths    []string
	RetryOverflow bool
}

func runStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign string, sourceHosts, retryPaths []string, generation uint64) StrmRewriteResult {
	if generation != 0 && !strmConfigGenerationMatches(generation) {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "STRM 配置已变化，取消历史修复"
		})
		return StrmRewriteResult{}
	}
	normalizedBaseURL, err := normalizeStrmBaseURL(baseURL)
	if err != nil {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "STRM 基础地址无效"
		})
		return StrmRewriteResult{}
	}
	base, err := url.Parse(normalizedBaseURL)
	if err != nil || !md5SignPattern.MatchString(sign) {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "STRM 基础地址或签名无效"
		})
		return StrmRewriteResult{}
	}
	normalizedSourceHosts, err := normalizeStrmSourceHosts(sourceHosts)
	if err != nil || len(normalizedSourceHosts) == 0 {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Failed++
			status.LastError = "STRM 来源主机未正确配置"
		})
		return StrmRewriteResult{}
	}
	strmSyncGate.Lock()
	defer strmSyncGate.Unlock()
	if generation != 0 && !strmConfigGenerationMatches(generation) {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "STRM 配置已变化，取消历史修复"
		})
		return StrmRewriteResult{}
	}

	retrySet := make(map[string]struct{})
	var pendingRetryPaths []string
	retryOverflow := false
	addRetryPath := func(path string) {
		relativePath, err := strmRetryRelativePath(mediaDir, path)
		if err != nil {
			return
		}
		if _, exists := retrySet[relativePath]; exists {
			return
		}
		if len(pendingRetryPaths) >= maxStrmPendingRetryPaths {
			retryOverflow = true
			return
		}
		retrySet[relativePath] = struct{}{}
		pendingRetryPaths = append(pendingRetryPaths, relativePath)
	}

	processFile := func(path string) error {
		if generation != 0 && !strmConfigGenerationMatches(generation) {
			return errStrmConfigChanged
		}
		if !strings.EqualFold(filepath.Ext(path), ".strm") {
			return nil
		}

		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.Scanned++
		})
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			addRetryPath(path)
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Failed++
				status.LastError = fmt.Sprintf("文件 %s：读取 STRM 文件失败", filepath.Base(path))
			})
			return nil
		}
		source, needsRewrite, parseErr := parseStrmURL(content)
		if parseErr != nil {
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Failed++
				status.LastError = fmt.Sprintf("文件 %s：%v", filepath.Base(path), parseErr)
			})
			return nil
		}
		if !needsRewrite || !strmSourceOrTargetHostAllowed(source, normalizedSourceHosts, base) {
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Skipped++
			})
			return nil
		}
		changed, err := rewriteSTRMFileAtomicWithHosts(path, baseURL, sign, normalizedSourceHosts)
		if err != nil {
			addRetryPath(path)
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.Failed++
				status.LastError = fmt.Sprintf("文件 %s：%v", filepath.Base(path), err)
			})
			return nil
		}
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			if changed {
				status.Updated++
			} else {
				status.Skipped++
			}
		})
		return nil
	}

	var walkErr error
	if retryPaths == nil {
		recycleDir := filepath.Join(mediaDir, "recycle_bin")
		walkErr = filepath.WalkDir(mediaDir, func(path string, entry os.DirEntry, err error) error {
			if generation != 0 && !strmConfigGenerationMatches(generation) {
				return errStrmConfigChanged
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path == recycleDir {
					return filepath.SkipDir
				}
				return nil
			}
			return processFile(path)
		})
	} else {
		for _, relativePath := range normalizeStrmRetryPaths(retryPaths) {
			if generation != 0 && !strmConfigGenerationMatches(generation) {
				walkErr = errStrmConfigChanged
				break
			}
			path := filepath.Join(mediaDir, filepath.FromSlash(relativePath))
			info, statErr := os.Stat(path)
			if statErr != nil {
				if !os.IsNotExist(statErr) {
					addRetryPath(path)
					updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
						status.Failed++
						status.LastError = fmt.Sprintf("文件 %s：读取 STRM 文件信息失败", filepath.Base(path))
					})
				}
				continue
			}
			if info.IsDir() {
				continue
			}
			if err := processFile(path); err != nil {
				walkErr = err
				break
			}
		}
	}
	if walkErr != nil {
		if errors.Is(walkErr, errStrmConfigChanged) {
			updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
				status.LastError = "STRM 配置已变化，取消历史修复"
			})
			return StrmRewriteResult{}
		}
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "扫描媒体目录失败"
		})
	}
	if retryOverflow {
		updateStrmRewriteStatus(func(status *StrmRewriteStatus) {
			status.LastError = "失败过多，需要手工全量修复"
		})
	}
	// 单个 STRM 的解析失败视为永久异常；读取或原子替换失败进入待重试列表。
	// 只要目录遍历本身成功，本次签名状态即可落库，监控随后只重试这些路径。
	return StrmRewriteResult{Completed: walkErr == nil, RetryPaths: pendingRetryPaths, RetryOverflow: retryOverflow}
}

func persistStrmLastAppliedSign(sign, baseURL, signEndpoint, token string, sourceHosts []string) error {
	return persistStrmAppliedState(sign, baseURL, signEndpoint, token, sourceHosts, nil, false)
}

func persistStrmAppliedState(sign, baseURL, signEndpoint, token string, sourceHosts, retryPaths []string, retryOverflow bool) error {
	if !md5SignPattern.MatchString(sign) {
		return fmt.Errorf("签名无效")
	}
	normalizedBaseURL, err := normalizeStrmBaseURL(baseURL)
	if err != nil {
		return err
	}
	normalizedEndpoint, err := normalizeStrmSignEndpoint(signEndpoint)
	if err != nil {
		return err
	}
	normalizedHosts, err := normalizeStrmSourceHosts(sourceHosts)
	if err != nil {
		return err
	}
	tokenFingerprint := sha256.Sum256([]byte(strings.TrimSpace(token)))

	configMu.Lock()
	defer configMu.Unlock()
	if !config.StrmRewriteEnabled || config.StrmBaseURL != normalizedBaseURL || config.StrmSignEndpoint != normalizedEndpoint || !equalStrmHosts(config.StrmSourceHosts, normalizedHosts) {
		return fmt.Errorf("STRM 配置已变化")
	}
	currentToken, err := resolveStrmSignToken(config.StrmSignToken)
	if err != nil || sha256.Sum256([]byte(currentToken)) != tokenFingerprint {
		return fmt.Errorf("STRM token 已变化")
	}
	normalizedRetryPaths := normalizeStrmRetryPaths(retryPaths)
	if len(normalizedRetryPaths) > maxStrmPendingRetryPaths {
		normalizedRetryPaths = normalizedRetryPaths[:maxStrmPendingRetryPaths]
		retryOverflow = true
	}
	fingerprint, err := strmAppliedContentFingerprint(normalizedBaseURL, sign, normalizedHosts)
	if err != nil {
		return err
	}
	if config.StrmLastAppliedSign == sign && config.StrmLastAppliedFingerprint == fingerprint && equalStrmRetryPaths(config.StrmPendingRetryPaths, normalizedRetryPaths) && config.StrmPendingRetryOverflow == retryOverflow {
		return nil
	}
	previous := config.StrmLastAppliedSign
	previousFingerprint := config.StrmLastAppliedFingerprint
	previousRetryPaths := append([]string(nil), config.StrmPendingRetryPaths...)
	previousRetryOverflow := config.StrmPendingRetryOverflow
	config.StrmLastAppliedSign = sign
	config.StrmLastAppliedFingerprint = fingerprint
	config.StrmPendingRetryPaths = normalizedRetryPaths
	config.StrmPendingRetryOverflow = retryOverflow
	if err := saveConfigLocked(); err != nil {
		config.StrmLastAppliedSign = previous
		config.StrmLastAppliedFingerprint = previousFingerprint
		config.StrmPendingRetryPaths = previousRetryPaths
		config.StrmPendingRetryOverflow = previousRetryOverflow
		return err
	}
	return nil
}

func normalizeStrmRetryPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
			continue
		}
		cleanPath := filepath.Clean(filepath.FromSlash(path))
		if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			continue
		}
		if cleanPath == "recycle_bin" || strings.HasPrefix(cleanPath, "recycle_bin"+string(filepath.Separator)) {
			continue
		}
		if !strings.EqualFold(filepath.Ext(cleanPath), ".strm") {
			continue
		}
		normalizedPath := filepath.ToSlash(cleanPath)
		if _, exists := seen[normalizedPath]; exists {
			continue
		}
		seen[normalizedPath] = struct{}{}
		result = append(result, normalizedPath)
	}
	return result
}

func strmRetryRelativePath(mediaDir, path string) (string, error) {
	relativePath, err := filepath.Rel(mediaDir, path)
	if err != nil {
		return "", err
	}
	normalizedPaths := normalizeStrmRetryPaths([]string{relativePath})
	if len(normalizedPaths) != 1 {
		return "", fmt.Errorf("STRM 重试路径无效")
	}
	return normalizedPaths[0], nil
}

func equalStrmRetryPaths(left, right []string) bool {
	return equalStringSlices(normalizeStrmRetryPaths(left), normalizeStrmRetryPaths(right))
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalStrmHosts(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func strmAppliedContentFingerprint(baseURL, sign string, sourceHosts []string) (string, error) {
	if !md5SignPattern.MatchString(strings.TrimSpace(sign)) {
		return "", fmt.Errorf("签名无效")
	}
	normalizedBaseURL, err := normalizeStrmBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	normalizedHosts, err := normalizeStrmSourceHosts(sourceHosts)
	if err != nil {
		return "", err
	}
	value := strings.Join([]string{
		normalizedBaseURL,
		strings.TrimSpace(sign),
		strings.Join(normalizedHosts, "\x00"),
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest), nil
}

func currentStrmConfigGeneration() uint64 {
	configMu.RLock()
	defer configMu.RUnlock()
	return strmConfigGeneration
}

func strmConfigGenerationMatches(expected uint64) bool {
	if expected == 0 {
		return true
	}
	return currentStrmConfigGeneration() == expected
}

func startStrmSignMonitor(mediaDir string) {
	strmSignMonitorOnce.Do(func() {
		go func() {
			checkStrmSignAndScheduleRepair(mediaDir)
			ticker := time.NewTicker(strmSignMonitorInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					checkStrmSignAndScheduleRepair(mediaDir)
				case <-strmSignMonitorTrigger:
					checkStrmSignAndScheduleRepair(mediaDir)
				}
			}
		}()
	})
	requestStrmSignMonitor()
}

func requestStrmSignMonitor() {
	select {
	case strmSignMonitorTrigger <- struct{}{}:
	default:
	}
}

func delayStrmSignMonitorRetry(delay time.Duration) {
	strmSignMonitorRetryMu.Lock()
	strmSignMonitorRetryAt = time.Now().Add(delay)
	strmSignMonitorRetryMu.Unlock()
}

func resetStrmSignMonitorRetry() {
	strmSignMonitorRetryMu.Lock()
	strmSignMonitorRetryAt = time.Time{}
	strmSignMonitorRetryMu.Unlock()
}

func strmSignMonitorRetryBlocked() bool {
	strmSignMonitorRetryMu.Lock()
	defer strmSignMonitorRetryMu.Unlock()
	return time.Now().Before(strmSignMonitorRetryAt)
}

func checkStrmSignAndScheduleRepair(mediaDir string) {
	configMu.RLock()
	enabled := config.StrmRewriteEnabled
	baseURL := config.StrmBaseURL
	signEndpoint := config.StrmSignEndpoint
	signToken := config.StrmSignToken
	sourceHosts := append([]string(nil), config.StrmSourceHosts...)
	lastAppliedSign := config.StrmLastAppliedSign
	lastAppliedFingerprint := config.StrmLastAppliedFingerprint
	pendingRetryPaths := normalizeStrmRetryPaths(config.StrmPendingRetryPaths)
	pendingRetryOverflow := config.StrmPendingRetryOverflow
	if len(pendingRetryPaths) > maxStrmPendingRetryPaths {
		pendingRetryPaths = pendingRetryPaths[:maxStrmPendingRetryPaths]
		pendingRetryOverflow = true
	}
	generation := strmConfigGeneration
	configMu.RUnlock()
	if !enabled {
		return
	}
	if strmSignMonitorRetryBlocked() {
		return
	}
	resolvedToken, err := resolveStrmSignToken(signToken)
	if err != nil {
		return
	}
	sign, _, _, usedStale, err := strmSignCache.GetWithChange(context.Background(), signEndpoint, resolvedToken)
	if err != nil || usedStale {
		return
	}
	fingerprint, err := strmAppliedContentFingerprint(baseURL, sign, sourceHosts)
	if err != nil {
		return
	}
	needsFullRepair := sign != lastAppliedSign || fingerprint != lastAppliedFingerprint
	if !needsFullRepair && (pendingRetryOverflow || len(pendingRetryPaths) == 0) {
		return
	}
	onSuccess := func(result StrmRewriteResult) error {
		return persistStrmAppliedState(sign, baseURL, signEndpoint, resolvedToken, sourceHosts, result.RetryPaths, result.RetryOverflow)
	}
	var started bool
	if needsFullRepair {
		started = startStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, nil, generation, onSuccess)
	} else {
		started = startStrmRewriteWithSignResultAtGeneration(mediaDir, baseURL, sign, sourceHosts, pendingRetryPaths, generation, onSuccess)
	}
	if started {
		addLog("info", "检测到 STRM 签名变化或存在待重试文件，已启动历史修复")
	}
}
