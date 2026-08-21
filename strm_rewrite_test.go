package main

import (
	"bytes"
	"container/ring"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSign = "0123456789abcdef0123456789abcdef"

func TestRewriteSTRMContent(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		baseURL    string
		want       string
		wantChange bool
		wantErr    bool
	}{
		{
			name:       "无查询参数增加 sign",
			content:    "http://xiaoya.host:5678/d/path/video.mp4",
			baseURL:    "http://192.168.101.200:5678",
			want:       "http://192.168.101.200:5678/d/path/video.mp4?sign=" + testSign + "\n",
			wantChange: true,
		},
		{
			name:       "保留查询参数并替换旧 sign",
			content:    "http://old-host/d/path/video.mp4?foo=1&sign=old&sign=older",
			baseURL:    "http://new-host/",
			want:       "http://new-host/d/path/video.mp4?foo=1&sign=" + testSign + "\n",
			wantChange: true,
		},
		{
			name:       "中文路径",
			content:    "http://old-host/d/动漫/儿童/视频.mp4",
			baseURL:    "https://nas.example/media/",
			want:       "https://nas.example/media/d/%E5%8A%A8%E6%BC%AB/%E5%84%BF%E7%AB%A5/%E8%A7%86%E9%A2%91.mp4?sign=" + testSign + "\n",
			wantChange: true,
		},
		{
			name:       "已编码路径不重复编码",
			content:    "http://old-host/d/%E5%8A%A8%E6%BC%AB/foo%20bar.mp4",
			baseURL:    "http://192.168.101.200:5678",
			want:       "http://192.168.101.200:5678/d/%E5%8A%A8%E6%BC%AB/foo%20bar.mp4?sign=" + testSign + "\n",
			wantChange: true,
		},
		{
			name:    "非 d 路径跳过",
			content: "http://old-host/movie/video.mp4\n",
			baseURL: "http://new-host",
			want:    "http://old-host/movie/video.mp4\n",
		},
		{
			name:    "非 HTTP 协议跳过",
			content: "magnet:?xt=urn:btih:abc",
			baseURL: "http://new-host",
			want:    "magnet:?xt=urn:btih:abc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, changed, err := rewriteSTRMContent([]byte(test.content), test.baseURL, testSign)
			if (err != nil) != test.wantErr {
				t.Fatalf("错误 = %v, wantErr = %v", err, test.wantErr)
			}
			if string(got) != test.want {
				t.Fatalf("内容 = %q, want %q", got, test.want)
			}
			if changed != test.wantChange {
				t.Fatalf("changed = %v, want %v", changed, test.wantChange)
			}
		})
	}
}

func TestRewriteSTRMContentValidation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		baseURL string
		sign    string
	}{
		{name: "空文件", content: "", baseURL: "http://new-host", sign: testSign},
		{name: "多行内容", content: "http://old-host/d/a\nhttp://old-host/d/b", baseURL: "http://new-host", sign: testSign},
		{name: "非法 URL", content: "not-a-url", baseURL: "http://new-host", sign: testSign},
		{name: "基础地址带查询参数", content: "http://old-host/d/a", baseURL: "http://new-host/base?x=1", sign: testSign},
		{name: "无效 sign", content: "http://old-host/d/a", baseURL: "http://new-host", sign: "old"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := rewriteSTRMContent([]byte(test.content), test.baseURL, test.sign); err == nil {
				t.Fatal("期望返回错误")
			}
		})
	}
}

func TestNormalizeStrmBaseURL(t *testing.T) {
	got, err := normalizeStrmBaseURL("HTTP://example.test/base///")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://example.test/base" {
		t.Fatalf("基础地址 = %q", got)
	}
	for _, value := range []string{"", "ftp://example.test", "http://example.test/base?sign=x", "http://example.test/base#fragment"} {
		if _, err := normalizeStrmBaseURL(value); err == nil {
			t.Fatalf("地址 %q 应该无效", value)
		}
	}
}

func TestNormalizeStrmSignEndpointTrustBoundary(t *testing.T) {
	for _, value := range []string{
		"http://xiaoya/api/getsignmd5",
		"http://127.0.0.1:8080/api/getsignmd5",
		"http://192.168.101.200:5678/api/getsignmd5",
	} {
		if _, err := normalizeStrmSignEndpoint(value); err != nil {
			t.Fatalf("签名接口地址 %q 不应无效: %v", value, err)
		}
	}
	for _, value := range []string{
		"https://example.com/api/getsignmd5",
		"http://attacker.example/api/getsignmd5",
		"http://169.254.1.1/api/getsignmd5",
		"http://[fe80::1]/api/getsignmd5",
		"http://xiaoya/other",
		"http://xiaoya/api/getsignmd5?redirect=https://example.com",
	} {
		if _, err := normalizeStrmSignEndpoint(value); err == nil {
			t.Fatalf("签名接口地址 %q 应该无效", value)
		}
	}
}

func TestNormalizeStrmSourceHosts(t *testing.T) {
	got, err := normalizeStrmSourceHosts([]string{" Xiaoya.Host:5678 ", "xiaoya.host:5678", "192.168.101.200"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xiaoya.host:5678", "192.168.101.200"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("来源主机 = %#v, want %#v", got, want)
	}
	for _, value := range []string{"http://xiaoya.host", "xiaoya.host/path", "xiaoya.host:0", "xiaoya.host:65536"} {
		if _, err := normalizeStrmSourceHosts([]string{value}); err == nil {
			t.Fatalf("来源主机 %q 应该无效", value)
		}
	}
}

func TestSignCacheConcurrentRefreshesOnce(t *testing.T) {
	var requests atomic.Int32
	var invalidRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "test-token" || r.Header.Get("Content-Type") != "text/plain" || string(body) != strmSignCommand {
			invalidRequests.Add(1)
		}
		time.Sleep(20 * time.Millisecond)
		io.WriteString(w, testSign)
	}))
	defer server.Close()

	cache := newSignCache()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sign, _, _, err := cache.Get(context.Background(), server.URL, "test-token")
			if err != nil || sign != testSign {
				t.Errorf("获取 sign 失败: sign=%q err=%v", sign, err)
			}
		}()
	}
	wg.Wait()
	if got := requests.Load(); got != 1 {
		t.Fatalf("签名请求数 = %d, want 1", got)
	}
	if invalidRequests.Load() != 0 {
		t.Fatal("签名请求方法、header 或 body 不符合接口约定")
	}
}

func TestSignCacheReportsSignChangeAfterRefresh(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			io.WriteString(w, testSign)
			return
		}
		io.WriteString(w, "fedcba9876543210fedcba9876543210")
	}))
	defer server.Close()

	cache := newSignCache()
	if sign, _, changed, _, err := cache.GetWithChange(context.Background(), server.URL, "test-token"); err != nil || sign != testSign || !changed {
		t.Fatalf("首次获取 sign 结果错误: sign=%q changed=%v err=%v", sign, changed, err)
	}
	cache.mu.Lock()
	cache.expiresAt = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	sign, refreshed, changed, usedStale, err := cache.GetWithChange(context.Background(), server.URL, "test-token")
	if err != nil || sign != "fedcba9876543210fedcba9876543210" || !refreshed || !changed || usedStale {
		t.Fatalf("签名变化结果错误: sign=%q refreshed=%v changed=%v usedStale=%v err=%v", sign, refreshed, changed, usedStale, err)
	}
}

func TestResolveStrmSignTokenFileTakesPrecedence(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "alist_auth_token.txt")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(strmSignTokenFileEnv, tokenFile)
	token, err := resolveStrmSignToken("config-token")
	if err != nil || token != "file-token" {
		t.Fatalf("token 文件解析错误: token=%q err=%v", token, err)
	}
}

func TestHandleConfigRejectsStrmSignEndpointChange(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(`{"strmSignEndpoint":"http://192.168.1.10/api/getsignmd5"}`))
	response := httptest.NewRecorder()
	handleConfig(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if strings.Contains(response.Body.String(), "192.168.1.10") {
		t.Fatal("错误响应不应回显签名接口地址")
	}
}

func TestHistoricalRepairPersistsAppliedSignOnlyAfterSuccess(t *testing.T) {
	mediaDir := t.TempDir()
	strmPath := filepath.Join(mediaDir, "video.strm")
	if err := os.WriteFile(strmPath, []byte("http://xiaoya.host:5678/d/video.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}
	oldConfig := config
	oldLogs := logs
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   defaultStrmSignEndpoint,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host:5678"},
	}
	logs = ring.New(10)
	defer func() {
		config = oldConfig
		logs = oldLogs
	}()

	if !runStrmRewriteWithSign(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}) {
		t.Fatal("历史 STRM 修复不应失败")
	}
	content, err := os.ReadFile(strmPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "sign="+testSign) {
		t.Fatalf("历史 STRM 未使用新签名: %q", content)
	}
	if err := persistStrmLastAppliedSign(testSign, "http://new-host", defaultStrmSignEndpoint, "test-token", []string{"xiaoya.host:5678"}); err != nil {
		t.Fatalf("保存已应用签名失败: %v", err)
	}
	if config.StrmLastAppliedSign != testSign {
		t.Fatalf("已应用签名 = %q, want %q", config.StrmLastAppliedSign, testSign)
	}
}

func TestHistoricalRepairContinuesAfterMalformedFile(t *testing.T) {
	mediaDir := t.TempDir()
	goodPath := filepath.Join(mediaDir, "good.strm")
	badPath := filepath.Join(mediaDir, "broken.strm")
	if err := os.WriteFile(goodPath, []byte("http://xiaoya.host:5678/d/video.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badPath, nil, 0600); err != nil {
		t.Fatal(err)
	}

	strmRewriteStatusMu.Lock()
	oldStatus := strmRewriteStatus
	strmRewriteStatus = StrmRewriteStatus{}
	strmRewriteStatusMu.Unlock()
	defer func() {
		strmRewriteStatusMu.Lock()
		strmRewriteStatus = oldStatus
		strmRewriteStatusMu.Unlock()
	}()

	if !runStrmRewriteWithSign(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}) {
		t.Fatal("单个异常 STRM 不应使全库修复失败")
	}
	status := getStrmRewriteStatus()
	if status.Failed != 1 {
		t.Fatalf("异常文件计数 = %d, want 1", status.Failed)
	}
	content, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "sign="+testSign) {
		t.Fatalf("正常 STRM 未使用新签名: %q", content)
	}
}

func TestHistoricalRepairRecordsParseFailureReport(t *testing.T) {
	mediaDir := t.TempDir()
	badPath := filepath.Join(mediaDir, "broken.strm")
	if err := os.WriteFile(badPath, []byte("http://xiaoya.host:5678/d/video100%!.mp4"), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := config
	config = Config{StrmParseFailureReports: nil}
	defer func() { config = oldConfig }()

	result := runStrmRewriteWithSignResultAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, nil, 0)
	if !result.Completed {
		t.Fatal("解析失败文件不应使全量扫描失败")
	}
	if len(result.ParseFailureReports) != 1 {
		t.Fatalf("解析失败报告数量 = %d, want 1", len(result.ParseFailureReports))
	}
	if result.ParseFailureReports[0].Path != "broken.strm" {
		t.Fatalf("解析失败路径 = %q, want broken.strm", result.ParseFailureReports[0].Path)
	}
	if !strings.Contains(result.ParseFailureReports[0].Reason, "URL") {
		t.Fatalf("解析失败原因 = %q", result.ParseFailureReports[0].Reason)
	}
}

func TestParseFailureRepairTargetsReportOnly(t *testing.T) {
	mediaDir := t.TempDir()
	badPath := filepath.Join(mediaDir, "broken.strm")
	otherPath := filepath.Join(mediaDir, "other.strm")
	if err := os.WriteFile(badPath, []byte("http://xiaoya.host:5678/d/video100%!.mp4"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte("http://xiaoya.host:5678/d/other.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := config
	config = Config{StrmParseFailureReports: nil}
	defer func() { config = oldConfig }()

	first := runStrmRewriteWithSignResultAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, nil, 0)
	if len(first.ParseFailureReports) != 1 {
		t.Fatalf("首次解析失败报告 = %#v", first.ParseFailureReports)
	}
	config.StrmParseFailureReports = first.ParseFailureReports
	if err := os.WriteFile(badPath, []byte("http://xiaoya.host:5678/d/video100%25!.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	otherBefore, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}

	second := runStrmParseFailureRewriteAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, first.ParseFailureReports, 0)
	if !second.Completed || len(second.ParseFailureReports) != 0 {
		t.Fatalf("定向解析失败修复结果 = %#v", second)
	}
	content, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "sign="+testSign) {
		t.Fatalf("报告文件未被修复: %q", content)
	}
	otherAfter, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(otherAfter) != string(otherBefore) {
		t.Fatalf("定向修复修改了报告外文件: before=%q after=%q", otherBefore, otherAfter)
	}
}

func TestPersistStrmParseFailureReportsCaps(t *testing.T) {
	mediaDir := t.TempDir()
	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}

	oldConfig := config
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   defaultStrmSignEndpoint,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host:5678"},
	}
	defer func() { config = oldConfig }()

	reports := make([]StrmParseFailure, maxStrmParseFailureReports+1)
	for i := range reports {
		reports[i] = StrmParseFailure{
			Path:   filepath.Join("nested", strconv.Itoa(i), "broken.strm"),
			Reason: "STRM URL 解析失败",
		}
	}
	result := StrmRewriteResult{
		ParseFailureReports:     reports,
		ParseFailureOverflow:    true,
		ParseFailureReportReady: true,
	}
	if err := persistStrmAppliedStateFromResult(testSign, "http://new-host", defaultStrmSignEndpoint, "test-token", []string{"xiaoya.host:5678"}, result); err != nil {
		t.Fatal(err)
	}
	if len(config.StrmParseFailureReports) != maxStrmParseFailureReports {
		t.Fatalf("解析失败报告数量 = %d, want %d", len(config.StrmParseFailureReports), maxStrmParseFailureReports)
	}
	if !config.StrmParseFailureOverflow {
		t.Fatal("解析失败报告超过上限时应保留溢出标记")
	}
}

func TestPersistStrmStaleScanResultReplacesRetryPathsWithoutApplyingSign(t *testing.T) {
	mediaDir := t.TempDir()
	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}

	oldConfig := config
	config = Config{
		StrmRewriteEnabled:         true,
		StrmBaseURL:                "http://new-host",
		StrmSignEndpoint:           defaultStrmSignEndpoint,
		StrmSignToken:              "test-token",
		StrmSourceHosts:            []string{"xiaoya.host:5678"},
		StrmLastAppliedSign:        "old-sign",
		StrmLastAppliedFingerprint: "old-fingerprint",
		StrmPendingRetryPaths:      []string{"already-fixed.strm"},
		StrmParseFailureReports: []StrmParseFailure{{
			Path:   "old-broken.strm",
			Reason: "旧报告",
		}},
	}
	defer func() { config = oldConfig }()

	result := StrmRewriteResult{
		RetryPaths: []string{"new-retry.strm"},
		ParseFailureReports: []StrmParseFailure{{
			Path:   "new-broken.strm",
			Reason: "新报告",
		}},
		ParseFailureReportReady: true,
	}
	if err := persistStrmStaleScanResult("http://new-host", defaultStrmSignEndpoint, "test-token", []string{"xiaoya.host:5678"}, result); err != nil {
		t.Fatal(err)
	}
	if config.StrmLastAppliedSign != "old-sign" || config.StrmLastAppliedFingerprint != "old-fingerprint" {
		t.Fatalf("stale 扫描不应更新已应用签名状态: sign=%q fingerprint=%q", config.StrmLastAppliedSign, config.StrmLastAppliedFingerprint)
	}
	if !equalStrmRetryPaths(config.StrmPendingRetryPaths, []string{"new-retry.strm"}) {
		t.Fatalf("stale 全量扫描应替换待重试路径: %#v", config.StrmPendingRetryPaths)
	}
	if !equalStrmParseFailureReports(config.StrmParseFailureReports, result.ParseFailureReports) {
		t.Fatalf("stale 全量扫描应替换解析失败报告: %#v", config.StrmParseFailureReports)
	}
}

func TestParseFailureReportEndpointReturnsPathsAndReasons(t *testing.T) {
	oldConfig := config
	config = Config{
		StrmParseFailureReports: []StrmParseFailure{{
			Path:   "nested/broken.strm",
			Reason: "STRM URL 解析失败",
		}},
	}
	defer func() { config = oldConfig }()

	response := httptest.NewRecorder()
	handleStrmParseFailures(response, httptest.NewRequest(http.MethodGet, "/api/strm/parse-failures", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want %d", response.Code, http.StatusOK)
	}
	var report struct {
		Count    int                `json:"count"`
		Failures []StrmParseFailure `json:"failures"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Count != 1 || len(report.Failures) != 1 || report.Failures[0].Path != "nested/broken.strm" {
		t.Fatalf("解析失败报告 = %#v", report)
	}
}

func TestHistoricalRepairRetriesTransientFileFailuresOnly(t *testing.T) {
	mediaDir := t.TempDir()
	retryPath := filepath.Join(mediaDir, "retry.strm")
	otherPath := filepath.Join(mediaDir, "other.strm")
	if err := os.Symlink("missing-target", retryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte("http://xiaoya.host:5678/d/other.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}

	first := runStrmRewriteWithSignResultAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, nil, 0)
	if !first.Completed {
		t.Fatal("包含单文件读取失败时全库扫描不应失败")
	}
	if len(first.RetryPaths) != 1 || first.RetryPaths[0] != "retry.strm" {
		t.Fatalf("待重试路径 = %#v, want [retry.strm]", first.RetryPaths)
	}
	otherBeforeRetry, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(retryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retryPath, []byte("http://xiaoya.host:5678/d/retry.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second := runStrmRewriteWithSignResultAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, first.RetryPaths, 0)
	if !second.Completed || len(second.RetryPaths) != 0 {
		t.Fatalf("待重试文件处理结果 = %#v", second)
	}
	retryContent, err := os.ReadFile(retryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(retryContent), "sign="+testSign) {
		t.Fatalf("待重试 STRM 未更新: %q", retryContent)
	}
	otherContent, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(otherContent) != string(otherBeforeRetry) {
		t.Fatalf("待重试模式修改了其他 STRM: before=%q after=%q", otherBeforeRetry, otherContent)
	}
}

func TestStrmAppliedContentFingerprintUsesOutputInputs(t *testing.T) {
	base := "http://new-host"
	hosts := []string{"xiaoya.host:5678"}
	first, err := strmAppliedContentFingerprint(base, testSign, hosts)
	if err != nil {
		t.Fatal(err)
	}
	same, err := strmAppliedContentFingerprint(base, testSign, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if first != same {
		t.Fatal("相同媒体输出输入的指纹不一致")
	}
	changedSign, err := strmAppliedContentFingerprint(base, "fedcba9876543210fedcba9876543210", hosts)
	if err != nil {
		t.Fatal(err)
	}
	if first == changedSign {
		t.Fatal("签名变化未反映到媒体内容指纹")
	}
}

func TestPersistStrmAppliedStateCapsRetryPaths(t *testing.T) {
	mediaDir := t.TempDir()
	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}

	oldConfig := config
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   defaultStrmSignEndpoint,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host:5678"},
	}
	defer func() { config = oldConfig }()

	retryPaths := make([]string, maxStrmPendingRetryPaths+1)
	for i := range retryPaths {
		retryPaths[i] = filepath.Join("nested", strconv.Itoa(i), "video.strm")
	}
	if err := persistStrmAppliedState(testSign, "http://new-host", defaultStrmSignEndpoint, "test-token", []string{"xiaoya.host:5678"}, retryPaths, false); err != nil {
		t.Fatal(err)
	}
	if len(config.StrmPendingRetryPaths) != maxStrmPendingRetryPaths {
		t.Fatalf("待重试路径数量 = %d, want %d", len(config.StrmPendingRetryPaths), maxStrmPendingRetryPaths)
	}
	if !config.StrmPendingRetryOverflow {
		t.Fatal("超过上限时应标记为需要手工全量修复")
	}
}

func TestSignMonitorRepairsAndPersistsNewSign(t *testing.T) {
	mediaDir := t.TempDir()
	strmPath := filepath.Join(mediaDir, "video.strm")
	if err := os.WriteFile(strmPath, []byte("http://xiaoya.host:5678/d/video.mp4?sign=old\n"), 0600); err != nil {
		t.Fatal(err)
	}

	signServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testSign)
	}))
	defer signServer.Close()
	signEndpoint := signServer.URL + "/api/getsignmd5"

	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}
	oldConfig := config
	oldCache := strmSignCache
	oldLogs := logs
	oldLocation := shanghaiLoc
	strmRewriteStatusMu.Lock()
	oldStatus := strmRewriteStatus
	strmRewriteStatus = StrmRewriteStatus{}
	strmRewriteStatusMu.Unlock()
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   signEndpoint,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host:5678"},
	}
	strmSignCache = newSignCache()
	logs = ring.New(10)
	shanghaiLoc = time.UTC
	defer func() {
		config = oldConfig
		strmSignCache = oldCache
		logs = oldLogs
		shanghaiLoc = oldLocation
		strmRewriteStatusMu.Lock()
		strmRewriteStatus = oldStatus
		strmRewriteStatusMu.Unlock()
	}()

	checkStrmSignAndScheduleRepair(mediaDir)
	deadline := time.Now().Add(2 * time.Second)
	for {
		status := getStrmRewriteStatus()
		if !status.Running && !status.FinishedAt.IsZero() {
			if status.Failed != 0 {
				t.Fatalf("自动历史修复失败: %#v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("自动历史修复未完成")
		}
		time.Sleep(5 * time.Millisecond)
	}
	configMu.RLock()
	lastAppliedSign := config.StrmLastAppliedSign
	configMu.RUnlock()
	if lastAppliedSign != testSign {
		t.Fatalf("自动修复后已应用签名 = %q, want %q", lastAppliedSign, testSign)
	}
	content, err := os.ReadFile(strmPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "sign="+testSign) {
		t.Fatalf("自动修复未更新 STRM: %q", content)
	}
}

func TestHistoricalRepairSkipsStaleConfigGeneration(t *testing.T) {
	mediaDir := t.TempDir()
	strmPath := filepath.Join(mediaDir, "video.strm")
	original := "http://xiaoya.host:5678/d/video.mp4?sign=old\n"
	if err := os.WriteFile(strmPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := config
	oldGeneration := strmConfigGeneration
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   defaultStrmSignEndpoint,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host:5678"},
	}
	strmConfigGeneration = 10
	defer func() {
		config = oldConfig
		strmConfigGeneration = oldGeneration
	}()

	if runStrmRewriteWithSignAtGeneration(mediaDir, "http://new-host", testSign, []string{"xiaoya.host:5678"}, 11) {
		t.Fatal("配置代际过期时不应执行历史修复")
	}
	content, err := os.ReadFile(strmPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != original {
		t.Fatalf("过期配置代际仍修改了 STRM: %q", content)
	}
}

func TestSignCacheUsesStaleSignAfterRefreshFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			io.WriteString(w, testSign)
			return
		}
		http.Error(w, "failure", http.StatusForbidden)
	}))
	defer server.Close()

	cache := newSignCache()
	if sign, _, _, err := cache.Get(context.Background(), server.URL, "test-token"); err != nil || sign != testSign {
		t.Fatalf("首次获取 sign 失败: sign=%q err=%v", sign, err)
	}
	cache.mu.Lock()
	cache.expiresAt = time.Now().Add(-time.Second)
	cache.staleUntil = time.Now().Add(time.Minute)
	cache.mu.Unlock()
	sign, refreshed, usedStale, err := cache.Get(context.Background(), server.URL, "test-token")
	if err != nil || sign != testSign || refreshed || !usedStale {
		t.Fatalf("旧 sign 回退结果错误: sign=%q refreshed=%v usedStale=%v err=%v", sign, refreshed, usedStale, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("签名请求数 = %d, want 2", requests.Load())
	}
}

func TestSignCacheStaleFailureUsesRetryBackoff(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			io.WriteString(w, testSign)
			return
		}
		time.Sleep(20 * time.Millisecond)
		http.Error(w, "failure", http.StatusForbidden)
	}))
	defer server.Close()

	cache := newSignCache()
	if _, _, _, err := cache.Get(context.Background(), server.URL, "test-token"); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	cache.expiresAt = time.Now().Add(-time.Second)
	cache.staleUntil = time.Now().Add(time.Minute)
	cache.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sign, _, usedStale, err := cache.Get(context.Background(), server.URL, "test-token")
			if err != nil || sign != testSign || !usedStale {
				t.Errorf("并发旧 sign 回退失败: sign=%q usedStale=%v err=%v", sign, usedStale, err)
			}
		}()
	}
	wg.Wait()
	if requests.Load() != 2 {
		t.Fatalf("过期签名并发刷新请求数 = %d, want 2", requests.Load())
	}
}

func TestSignCacheInitialFailureUsesRetryBackoff(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "failure", http.StatusForbidden)
	}))
	defer server.Close()

	cache := newSignCache()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, err := cache.Get(context.Background(), server.URL, "test-token"); err == nil {
				t.Error("首次签名失败时应返回错误")
			}
		}()
	}
	wg.Wait()
	if requests.Load() != 1 {
		t.Fatalf("首次签名失败后的并发请求数 = %d, want 1", requests.Load())
	}
}

func TestSignCacheDoesNotFollowRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		io.WriteString(w, testSign)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	cache := newSignCache()
	if _, _, _, err := cache.Get(context.Background(), source.URL, "test-token"); err == nil {
		t.Fatal("签名接口重定向时应失败，不能继续发送 token")
	}
	if redirectedRequests.Load() != 0 {
		t.Fatal("签名请求不应跟随重定向")
	}
}

func TestSignCacheUsesDirectTransport(t *testing.T) {
	client := newDirectSignHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("签名客户端 transport 类型 = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("签名客户端不应继承环境代理")
	}
}

func TestSaveConfigConcurrentSnapshots(t *testing.T) {
	mediaDir := t.TempDir()
	mediaFlag := flag.Lookup("media")
	oldMediaDir := ""
	if mediaFlag == nil {
		flag.String("media", mediaDir, "test media directory")
	} else {
		oldMediaDir = mediaFlag.Value.String()
		if err := mediaFlag.Value.Set(mediaDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = mediaFlag.Value.Set(oldMediaDir) }()
	}

	oldConfig := config
	config = Config{
		PathUpdateNotices:  make(map[string]bool),
		ServerPathCounts:   make(map[string]int),
		LocalPathCounts:    make(map[string]int),
		StrmSourceHosts:    []string{"xiaoya.host"},
		StrmSignEndpoint:   defaultStrmSignEndpoint,
		StrmSignToken:      "not-logged",
		StrmRewriteEnabled: true,
	}
	defer func() { config = oldConfig }()

	var wg sync.WaitGroup
	errors := make(chan error, 32)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iteration := 0; iteration < 4; iteration++ {
				configMu.Lock()
				config.PathUpdateNotices[strconv.Itoa(worker)+"/"+strconv.Itoa(iteration)] = true
				configMu.Unlock()
				if err := saveConfig(); err != nil {
					errors <- err
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	file, err := os.Open(filepath.Join(mediaDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var persisted Config
	if err := json.NewDecoder(file).Decode(&persisted); err != nil {
		t.Fatalf("并发保存后的配置不是有效 JSON: %v", err)
	}
}

func TestNotifyIntervalChangeKeepsLatest(t *testing.T) {
	for {
		select {
		case <-intervalChange:
		default:
			goto drained
		}
	}

drained:
	notifyIntervalChange(2)
	notifyIntervalChange(3)
	select {
	case got := <-intervalChange:
		if got != 3 {
			t.Fatalf("同步间隔通知 = %d, want 3", got)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到同步间隔通知")
	}
}

func TestHandleConfigRollsBackLogBufferOnValidationFailure(t *testing.T) {
	oldConfig := config
	oldLogs := logs
	oldLocation := shanghaiLoc
	config = Config{LogSize: 2, Interval: 1}
	logs = ring.New(2)
	shanghaiLoc = time.UTC
	defer func() {
		config = oldConfig
		logs = oldLogs
		shanghaiLoc = oldLocation
	}()

	addLog("info", "保留的日志")
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(`{"logSize":5,"bandwidthLimitMBps":0}`))
	response := httptest.NewRecorder()
	handleConfig(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, want %d", response.Code, http.StatusBadRequest)
	}
	configMu.RLock()
	gotLogSize := config.LogSize
	configMu.RUnlock()
	if gotLogSize != 2 {
		t.Fatalf("日志大小 = %d, want 2", gotLogSize)
	}
	entries, _ := getLogs(10, 1, "", "")
	foundOriginal := false
	for _, entry := range entries {
		if entry.Message == "保留的日志" {
			foundOriginal = true
			break
		}
	}
	if !foundOriginal {
		t.Fatal("校验失败后未恢复原日志内容")
	}
}

func TestScanLocalFilesSkipsSTRMRewriteTempFiles(t *testing.T) {
	mediaDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(mediaDir, "video.strm"), []byte("http://xiaoya.host/d/video\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mediaDir, ".video.strm.rewrite-12345"), []byte("temporary"), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := config
	oldLogs := logs
	oldLocation := shanghaiLoc
	config = Config{MemoryLimitMB: 512}
	logs = ring.New(10)
	shanghaiLoc = time.UTC
	defer func() {
		config = oldConfig
		logs = oldLogs
		shanghaiLoc = oldLocation
	}()

	local, err := scanLocalFilesToMap(mediaDir, []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := local.Files[".video.strm.rewrite-12345"]; ok {
		t.Fatal("STRM 重写临时文件不应进入本地文件映射")
	}
	if _, ok := local.Files["video.strm"]; !ok {
		t.Fatal("正式 STRM 文件应进入本地文件映射")
	}
}

func TestDownloadSignatureFailureKeepsExistingFile(t *testing.T) {
	mediaDir := t.TempDir()
	relativePath := filepath.Join("动漫", "video.strm")
	localPath := filepath.Join(mediaDir, relativePath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		t.Fatal(err)
	}
	oldContent := "http://old-host/d/old/video.mp4?sign=old\n"
	if err := os.WriteFile(localPath, []byte(oldContent), 0644); err != nil {
		t.Fatal(err)
	}

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "http://xiaoya.host/d/new/video.mp4\n")
	}))
	defer source.Close()
	var signRequests atomic.Int32
	signServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signRequests.Add(1)
		http.Error(w, "failure", http.StatusInternalServerError)
	}))
	defer signServer.Close()

	oldClient := httpClient
	oldCache := strmSignCache
	oldLogs := logs
	oldLocation := shanghaiLoc
	oldConfig := config
	httpClient = source.Client()
	strmSignCache = newSignCache()
	logs = ring.New(10)
	shanghaiLoc = time.UTC
	config = Config{
		StrmRewriteEnabled: true,
		StrmBaseURL:        "http://new-host",
		StrmSignEndpoint:   signServer.URL,
		StrmSignToken:      "test-token",
		StrmSourceHosts:    []string{"xiaoya.host"},
	}
	defer func() {
		httpClient = oldClient
		strmSignCache = oldCache
		logs = oldLogs
		shanghaiLoc = oldLocation
		config = oldConfig
	}()

	err := downloadFile(context.Background(), FileInfo{Path: "动漫/video.strm", Timestamp: time.Now().Unix()}, []ServerInfo{{URL: source.URL}}, mediaDir, relativePath)
	if err == nil {
		t.Fatal("签名失败时应返回错误")
	}
	if signRequests.Load() != 1 {
		t.Fatalf("签名请求数 = %d, want 1", signRequests.Load())
	}
	got, readErr := os.ReadFile(localPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != oldContent {
		t.Fatalf("正式文件被覆盖: %q", got)
	}
	if _, err := os.Stat(localPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("临时文件仍存在: %v", err)
	}
}

func TestDownloadSTRMRewriteDisabledKeepsContent(t *testing.T) {
	mediaDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "http://xiaoya.host/d/video.mp4?sign=old\n")
	}))
	defer server.Close()

	oldClient := httpClient
	oldLogs := logs
	oldLocation := shanghaiLoc
	oldConfig := config
	httpClient = server.Client()
	logs = ring.New(10)
	shanghaiLoc = time.UTC
	config = Config{StrmRewriteEnabled: false}
	defer func() {
		httpClient = oldClient
		logs = oldLogs
		shanghaiLoc = oldLocation
		config = oldConfig
	}()

	if err := downloadFile(context.Background(), FileInfo{Path: "动漫/video.strm", Timestamp: time.Now().Unix()}, []ServerInfo{{URL: server.URL}}, mediaDir, filepath.Join("动漫", "video.strm")); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(mediaDir, "动漫", "video.strm"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "http://xiaoya.host/d/video.mp4?sign=old\n" {
		t.Fatalf("关闭重写后内容被修改: %q", content)
	}
}

func TestRewriteSTRMContentSourceHostAllowlist(t *testing.T) {
	content := []byte("http://other.example/d/video.mp4\n")
	got, changed, err := rewriteSTRMContentWithHosts(content, "http://new-host", testSign, []string{"xiaoya.host:5678"})
	if err != nil {
		t.Fatal(err)
	}
	if changed || !bytes.Equal(got, content) {
		t.Fatalf("非允许来源被改写: changed=%v content=%q", changed, got)
	}

	content = []byte("http://xiaoya.host:5678/d/video.mp4\n")
	got, changed, err = rewriteSTRMContentWithHosts(content, "http://new-host", testSign, []string{"xiaoya.host:5678"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.HasPrefix(string(got), "http://new-host/d/video.mp4?sign=") {
		t.Fatalf("允许来源未被改写: changed=%v content=%q", changed, got)
	}

	content = []byte("http://new-host/d/video.mp4?sign=old\n")
	got, changed, err = rewriteSTRMContentWithHosts(content, "http://new-host", testSign, []string{"xiaoya.host:5678"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.Contains(string(got), "sign="+testSign) {
		t.Fatalf("已使用目标地址的 STRM 未刷新签名: changed=%v content=%q", changed, got)
	}

	content = []byte("http://new-host:80/d/video.mp4?sign=old\n")
	got, changed, err = rewriteSTRMContentWithHosts(content, "http://new-host", testSign, []string{"xiaoya.host:5678"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.Contains(string(got), "sign="+testSign) {
		t.Fatalf("目标地址默认端口未刷新签名: changed=%v content=%q", changed, got)
	}

	content = []byte("http://[fd00::1]/d/video.mp4\n")
	got, changed, err = rewriteSTRMContentWithHosts(content, "http://new-host", testSign, []string{"fd00::1"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.Contains(string(got), "sign="+testSign) {
		t.Fatalf("无端口 IPv6 来源未被允许: changed=%v content=%q", changed, got)
	}
}

func TestRewriteSTRMFileAtomicPreservesMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "video.strm")
	if err := os.WriteFile(path, []byte("http://old-host/d/video.mp4"), 0640); err != nil {
		t.Fatal(err)
	}
	originalTime := time.Unix(1700000000, 0)
	if err := os.Chtimes(path, originalTime, originalTime); err != nil {
		t.Fatal(err)
	}
	changed, err := rewriteSTRMFileAtomic(path, "http://new-host/", testSign)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("文件应被改写")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), "http://new-host/d/video.mp4?sign=") {
		t.Fatalf("改写内容错误: %q", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(originalTime) {
		t.Fatalf("mtime = %v, want %v", info.ModTime(), originalTime)
	}
}

func TestRewriteSTRMFileAtomicUsesShortTemporaryName(t *testing.T) {
	name := strings.Repeat("a", 240) + ".strm"
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("http://old-host/d/video.mp4"), 0640); err != nil {
		t.Fatal(err)
	}

	changed, err := rewriteSTRMFileAtomic(path, "http://new-host/", testSign)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("文件应被改写")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), "http://new-host/d/video.mp4?sign=") {
		t.Fatalf("改写内容错误: %q", content)
	}
}

func TestStartStrmRewritePreventsDuplicateTasks(t *testing.T) {
	oldStatus := getStrmRewriteStatus()
	defer func() {
		strmRewriteStatusMu.Lock()
		strmRewriteStatus = oldStatus
		strmRewriteStatusMu.Unlock()
	}()
	strmRewriteStatusMu.Lock()
	strmRewriteStatus = StrmRewriteStatus{Running: true}
	strmRewriteStatusMu.Unlock()
	if startStrmRewrite(t.TempDir(), "http://new-host", "http://sign.example", "test-token", []string{"xiaoya.host"}) {
		t.Fatal("已有任务运行时不应重复启动")
	}
}

func TestStrmSyncGateBlocksDownloadReaders(t *testing.T) {
	strmSyncGate.Lock()
	ready := make(chan struct{})
	go func() {
		strmSyncGate.RLock()
		close(ready)
		strmSyncGate.RUnlock()
	}()
	select {
	case <-ready:
		t.Fatal("历史修复持有写锁时 STRM 下载不应进入")
	case <-time.After(30 * time.Millisecond):
	}
	strmSyncGate.Unlock()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("释放历史修复锁后 STRM 下载仍未进入")
	}
}

func TestPublicConfigDoesNotExposeStrmToken(t *testing.T) {
	public := publicConfigResponse(Config{
		StrmSignToken:            "sensitive-token",
		StrmPendingRetryPaths:    []string{"private/path.strm"},
		StrmPendingRetryOverflow: true,
	})
	body, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("sensitive-token")) {
		t.Fatalf("配置响应泄露 token: %s", body)
	}
	if bytes.Contains(body, []byte("private/path.strm")) || bytes.Contains(body, []byte("pendingRetry")) {
		t.Fatalf("配置响应泄露待重试状态内部字段: %s", body)
	}
	if !bytes.Contains(body, []byte(`"strmSignTokenConfigured":true`)) {
		t.Fatalf("配置响应缺少 token 已配置状态: %s", body)
	}
}

func TestStrmRewriteStatusIncludesPersistedRetryState(t *testing.T) {
	oldConfig := config
	configMu.Lock()
	config = Config{
		StrmPendingRetryPaths:    []string{"one.strm", "two.strm"},
		StrmPendingRetryOverflow: true,
	}
	configMu.Unlock()
	defer func() {
		configMu.Lock()
		config = oldConfig
		configMu.Unlock()
	}()

	status := getStrmRewriteStatus()
	if status.PendingRetryCount != 2 {
		t.Fatalf("待重试数量 = %d, want 2", status.PendingRetryCount)
	}
	if !status.PendingRetryOverflow {
		t.Fatal("状态应保留待重试溢出标记")
	}
}
