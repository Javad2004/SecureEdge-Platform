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
	"path"
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

const (
	// Raw request samples are always inspected in full up to the configured
	// byte limits. Structured expansion is additionally bounded so a request
	// containing thousands of JSON properties, form fields, or query keys
	// cannot multiply into an unbounded number of regular-expression scans.
	maxStructuredSamples  = 512
	maxMatchLocationBytes = 256
)

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
		"headers": headerSamples(req, policy.MaxHeaderCount),
		"cookies": cookieSamples(req, policy.MaxHeaderCount),
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
				result.Score = saturatingAddScore(result.Score, rule.Score)
				result.Matches = append(result.Matches, Match{RuleID: rule.ID, RuleName: rule.Name, Category: rule.Category, Score: rule.Score, Target: target, Location: boundedMatchLocation(item.location), Fingerprint: fingerprint(item.value)})
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

func saturatingAddScore(current, increment int) int {
	if increment <= 0 {
		return current
	}
	maxInt := int(^uint(0) >> 1)
	if current > maxInt-increment {
		return maxInt
	}
	return current + increment
}

func excludedPathMatches(requestPath, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}
	// Canonicalize after bounded repeated path decoding before applying an
	// exclusion. net/http has already decoded the request path once, but a
	// double-encoded dot segment such as %252e%252e remains as %2e%2e in URL.Path.
	// If the application or another intermediary decodes it again, the request can
	// escape the excluded prefix. Fail closed by using the same bounded decoding
	// depth as WAF path inspection before resolving dot segments.
	requestPath = canonicalRequestPath(multiPathDecode(requestPath))
	if prefix == "/" || requestPath == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(requestPath, prefix)
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}

func canonicalRequestPath(value string) string {
	if value == "" {
		return "/"
	}
	trailingSlash := strings.HasSuffix(value, "/")
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
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
		if !appendStructuredSample(&out, sample{location: "query.name", value: normalize(key)}) {
			break
		}
		for idx, value := range values[key] {
			if !appendStructuredSample(&out, sample{location: boundedMatchLocation("query.value:" + key), value: normalize(value)}) {
				return out
			}
			if idx >= 31 {
				break
			}
		}
	}
	return out
}

func headerSamples(req *http.Request, maxFields int) []sample {
	if maxFields <= 0 {
		maxFields = 100
	}
	out := make([]sample, 0, minInt(maxFields*2, 512))
	fields := 0
	appendFields := func(header http.Header, nameLocation, valuePrefix string) bool {
		keys := make([]string, 0, len(header))
		for key := range header {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie") {
				continue
			}
			out = append(out, sample{location: nameLocation, value: name})
			values := header.Values(name)
			if len(values) == 0 {
				fields++
				if fields >= maxFields {
					return false
				}
				continue
			}
			for _, value := range values {
				out = append(out, sample{location: boundedMatchLocation(valuePrefix + strings.ToLower(name)), value: normalize(value)})
				fields++
				if fields >= maxFields {
					return false
				}
			}
		}
		return true
	}

	// net/http promotes Host out of Request.Header into Request.Host. It remains
	// a client-controlled HTTP header and must be inspected by rules targeting
	// headers, especially for wildcard routes that can forward the original Host
	// to a virtual-hosted Origin. Count it toward the same field cap used by the
	// gateway's request-shape validation.
	if req != nil && strings.TrimSpace(req.Host) != "" {
		out = append(out,
			sample{location: "header.name", value: "Host"},
			sample{location: "header:host", value: normalize(req.Host)},
		)
		fields++
		if fields >= maxFields {
			return out
		}
	}
	if req == nil {
		return out
	}
	if !appendFields(req.Header, "header.name", "header:") {
		return out
	}
	// HTTP trailers are application-visible header fields delivered after the
	// request body. The gateway stages trailer-bearing requests to EOF before WAF
	// inspection, so their populated values must be evaluated under the same
	// rules and field cap as ordinary headers.
	appendFields(req.Trailer, "trailer.name", "trailer:")
	return out
}

func cookieSamples(req *http.Request, maxHeaderFields int) []sample {
	if maxHeaderFields <= 0 {
		maxHeaderFields = 100
	}
	// Inspect each raw Cookie field as well as parsed cookie names and values.
	// The raw samples cover arbitrarily long cookie lists without retaining or
	// logging secret values; matches expose only a fingerprint.
	out := make([]sample, 0, 130)
	for idx, raw := range req.Header.Values("Cookie") {
		out = append(out, sample{location: "cookie.raw", value: normalize(raw)})
		if idx+1 >= maxHeaderFields {
			break
		}
	}
	for idx, cookie := range req.Cookies() {
		out = append(out, sample{location: "cookie.name", value: normalize(cookie.Name)})
		out = append(out, sample{location: boundedMatchLocation("cookie:" + cookie.Name), value: normalize(cookie.Value)})
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
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if !appendStructuredSample(&out, sample{location: "form.name", value: normalize(key)}) {
					break
				}
				list := values[key]
				for _, value := range list {
					if !appendStructuredSample(&out, sample{location: boundedMatchLocation("form.value:" + key), value: normalize(value)}) {
						return out
					}
				}
			}
		}
	}
	return out
}

func flattenJSON(out *[]sample, path string, value any, depth int) {
	if depth > 12 || len(*out) >= maxStructuredSamples {
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
			if !appendStructuredSample(out, sample{location: path + ".key", value: normalize(key)}) {
				return
			}
			flattenJSON(out, boundedMatchLocation(path+"."+key), v[key], depth+1)
			if len(*out) >= maxStructuredSamples {
				return
			}
		}
	case []any:
		for idx, item := range v {
			flattenJSON(out, path, item, depth+1)
			if len(*out) >= maxStructuredSamples {
				return
			}
			if idx >= 127 {
				break
			}
		}
	case string:
		appendStructuredSample(out, sample{location: path, value: normalize(v)})
	}
}

func appendStructuredSample(out *[]sample, item sample) bool {
	if len(*out) >= maxStructuredSamples {
		return false
	}
	*out = append(*out, item)
	return true
}

func boundedMatchLocation(value string) string {
	if len(value) <= maxMatchLocationBytes {
		return value
	}
	// Locations may include attacker-controlled query, form, cookie, or JSON
	// field names. Replace an oversized location with a stable fingerprint so
	// one match cannot inflate an in-memory or persisted security event by
	// megabytes while still remaining correlatable for diagnostics.
	return "oversized-field:" + fingerprint(value)
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

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

func readAndRestore(req *http.Request, max int64) ([]byte, bool, error) {
	original := req.Body
	buf, err := io.ReadAll(io.LimitReader(original, max+1))
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(buf)) > max
	inspect := buf
	if truncated {
		inspect = buf[:max]
		req.Body = &replayReadCloser{
			Reader: io.MultiReader(bytes.NewReader(buf), original),
			closer: original,
		}
	} else {
		_ = original.Close()
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
	}
	return inspect, truncated, nil
}

func multiPathDecode(value string) string {
	out := value
	for n := 0; n < 3; n++ {
		decoded, err := url.PathUnescape(out)
		if err != nil || decoded == out {
			break
		}
		out = decoded
	}
	return out
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
