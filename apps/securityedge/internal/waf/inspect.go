package waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

type Inspector struct {
	mu         sync.RWMutex
	rules      []Rule
	maxMatches int
}

func NewInspector(custom []config.CustomRuleConfig, maxMatches int) (*Inspector, error) {
	rules, err := CompileRules(custom)
	if err != nil {
		return nil, err
	}
	if maxMatches <= 0 {
		maxMatches = 32
	}
	return &Inspector{rules: rules, maxMatches: maxMatches}, nil
}

func (i *Inspector) Rules() []Rule {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Rule, len(i.rules))
	copy(out, i.rules)
	return out
}

func (i *Inspector) Replace(custom []config.CustomRuleConfig, maxMatches int) error {
	rules, err := CompileRules(custom)
	if err != nil {
		return err
	}
	if maxMatches <= 0 {
		maxMatches = 32
	}
	i.mu.Lock()
	i.rules, i.maxMatches = rules, maxMatches
	i.mu.Unlock()
	return nil
}

func (i *Inspector) Inspect(req *http.Request, policy config.Policy) (Result, error) {
	i.mu.RLock()
	rules := append([]Rule(nil), i.rules...)
	maxMatches := i.maxMatches
	i.mu.RUnlock()
	result := Result{Matches: []Match{}}
	for _, prefix := range policy.ExcludedPathPrefixes {
		if excludedPathMatches(req.URL.Path, prefix) {
			result.Excluded = true
			return result, nil
		}
	}
	disabled := make(map[string]bool, len(policy.DisabledRules))
	for _, id := range policy.DisabledRules {
		disabled[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	targets := map[string][]sample{
		"path":    pathSamples(req.URL),
		"query":   querySamples(req.URL),
		"headers": headerSamples(req.Header),
		"cookies": cookieSamples(req),
	}
	if policy.InspectRequestBody && policy.MaxInspectionBodyBytes > 0 && requestBodyTypeAllowed(req.Header.Get("Content-Type"), policy.BodyContentTypes) && req.Body != nil && req.Body != http.NoBody {
		body, truncated, err := readAndRestore(req, policy.MaxInspectionBodyBytes)
		if err != nil {
			return result, err
		}
		result.BodyInspected, result.BodyTruncated = true, truncated
		targets["body"] = bodySamples(body, req.Header.Get("Content-Type"))
	}
	for _, rule := range rules {
		if disabled[rule.ID] {
			continue
		}
		matched := false
		for _, target := range rule.Targets {
			for _, item := range targets[target] {
				if item.value == "" || !rule.pattern.MatchString(item.value) {
					continue
				}
				result.Score += rule.Score
				result.Matches = append(result.Matches, Match{RuleID: rule.ID, RuleName: rule.Name, Category: rule.Category, Score: rule.Score, Target: target, Location: item.location, Fingerprint: fingerprint(item.value)})
				matched = true
				if len(result.Matches) >= maxMatches {
					result.MatchLimitReached = true
					sortMatches(result.Matches)
					return result, nil
				}
				break
			}
			if matched {
				break
			}
		}
	}
	sortMatches(result.Matches)
	return result, nil
}

func excludedPathMatches(requestPath, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}
	if prefix == "/" || requestPath == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(requestPath, prefix)
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}

type sample struct{ location, value string }

func pathSamples(u *url.URL) []sample {
	raw := u.EscapedPath()
	decoded := multiDecode(raw)
	return []sample{
		{location: "url.path.raw", value: raw},
		{location: "url.path.decoded", value: decoded},
		{location: "url.path.normalized", value: normalize(decoded)},
	}
}

func querySamples(u *url.URL) []sample {
	out := []sample{
		{location: "url.query.raw", value: u.RawQuery},
		{location: "url.query.decoded", value: multiDecode(u.RawQuery)},
		{location: "url.query.normalized", value: normalize(multiDecode(u.RawQuery))},
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return out
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, sample{location: "query.name", value: normalize(key)})
		for idx, value := range values[key] {
			out = append(out, sample{location: "query.value:" + key, value: normalize(value)})
			if idx >= 31 {
				break
			}
		}
	}
	return out
}

func headerSamples(h http.Header) []sample {
	out := make([]sample, 0, len(h)*2)
	keys := make([]string, 0, len(h))
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie") {
			continue
		}
		out = append(out, sample{location: "header.name", value: name})
		for idx, value := range h.Values(name) {
			out = append(out, sample{location: "header:" + strings.ToLower(name), value: normalize(value)})
			if idx >= 15 {
				break
			}
		}
	}
	return out
}

func cookieSamples(req *http.Request) []sample {
	cookies := req.Cookies()
	out := make([]sample, 0, len(cookies)*2)
	for idx, cookie := range cookies {
		out = append(out, sample{location: "cookie.name", value: normalize(cookie.Name)})
		out = append(out, sample{location: "cookie:" + cookie.Name, value: normalize(cookie.Value)})
		if idx >= 63 {
			break
		}
	}
	return out
}

func bodySamples(body []byte, contentType string) []sample {
	text := string(bytes.ToValidUTF8(body, []byte("?")))
	out := []sample{{location: "request.body.raw", value: text}, {location: "request.body.normalized", value: normalize(text)}}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch strings.ToLower(mediaType) {
	case "application/json":
		var value any
		if json.Unmarshal(body, &value) == nil {
			flattenJSON(&out, "json", value, 0)
		}
	case "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(text); err == nil {
			for key, list := range values {
				out = append(out, sample{location: "form.name", value: normalize(key)})
				for _, value := range list {
					out = append(out, sample{location: "form.value:" + key, value: normalize(value)})
				}
			}
		}
	}
	return out
}

func flattenJSON(out *[]sample, path string, value any, depth int) {
	if depth > 12 || len(*out) >= 512 {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			*out = append(*out, sample{location: path + ".key", value: normalize(key)})
			flattenJSON(out, path+"."+key, v[key], depth+1)
		}
	case []any:
		for idx, item := range v {
			flattenJSON(out, path, item, depth+1)
			if idx >= 127 {
				break
			}
		}
	case string:
		*out = append(*out, sample{location: path, value: normalize(v)})
	}
}

func requestBodyTypeAllowed(raw string, allowed []string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(raw, ";")[0])
	}
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), mediaType) {
			return true
		}
	}
	return false
}

func readAndRestore(req *http.Request, max int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(req.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(buf)) > max
	inspect := buf
	if truncated {
		inspect = buf[:max]
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
	} else {
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
	}
	return inspect, truncated, nil
}

func multiDecode(value string) string {
	out := value
	for n := 0; n < 3; n++ {
		decoded, err := url.QueryUnescape(out)
		if err != nil || decoded == out {
			break
		}
		out = decoded
	}
	return out
}

func normalize(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = html.UnescapeString(value)
	value = multiDecode(value)
	value = strings.ReplaceAll(value, "\x00", "")
	if !utf8.ValidString(value) {
		value = string([]rune(value))
	}
	return value
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func sortMatches(matches []Match) {
	sort.SliceStable(matches, func(a, b int) bool {
		if matches[a].RuleID == matches[b].RuleID {
			return matches[a].Location < matches[b].Location
		}
		return matches[a].RuleID < matches[b].RuleID
	})
}
