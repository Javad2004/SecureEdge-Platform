package waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
)

type Inspector struct{ rules []Rule }

func NewInspector() *Inspector     { return &Inspector{rules: BuiltinRules()} }
func (i *Inspector) Rules() []Rule { out := make([]Rule, len(i.rules)); copy(out, i.rules); return out }

func (i *Inspector) Inspect(req *http.Request, policy config.Policy) (Result, error) {
	result := Result{Matches: []Match{}}
	for _, prefix := range policy.ExcludedPathPrefixes {
		if prefix != "" && strings.HasPrefix(req.URL.Path, prefix) {
			result.Excluded = true
			return result, nil
		}
	}
	disabled := make(map[string]bool, len(policy.DisabledRules))
	for _, id := range policy.DisabledRules {
		disabled[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	targets := map[string][]sample{
		"path":    {{location: "url.path.raw", value: req.URL.EscapedPath()}, {location: "url.path.decoded", value: multiDecode(req.URL.EscapedPath())}},
		"query":   querySamples(req.URL),
		"headers": headerSamples(req.Header),
	}
	if policy.InspectRequestBody && policy.MaxInspectionBodyBytes > 0 && requestBodyTypeAllowed(req.Header.Get("Content-Type"), policy.BodyContentTypes) && req.Body != nil && req.Body != http.NoBody {
		body, truncated, err := readAndRestore(req, policy.MaxInspectionBodyBytes)
		if err != nil {
			return result, err
		}
		result.BodyInspected, result.BodyTruncated = true, truncated
		targets["body"] = []sample{{location: "request.body", value: string(body)}}
	}
	for _, rule := range i.rules {
		if disabled[rule.ID] {
			continue
		}
		for _, target := range rule.Targets {
			for _, sample := range targets[target] {
				if sample.value == "" || !rule.pattern.MatchString(sample.value) {
					continue
				}
				result.Score += rule.Score
				result.Matches = append(result.Matches, Match{RuleID: rule.ID, RuleName: rule.Name, Category: rule.Category, Score: rule.Score, Target: target, Location: sample.location, Fingerprint: fingerprint(sample.value)})
			}
		}
	}
	sort.SliceStable(result.Matches, func(a, b int) bool {
		if result.Matches[a].RuleID == result.Matches[b].RuleID {
			return result.Matches[a].Location < result.Matches[b].Location
		}
		return result.Matches[a].RuleID < result.Matches[b].RuleID
	})
	return result, nil
}

type sample struct{ location, value string }

func querySamples(u *url.URL) []sample {
	out := []sample{{location: "url.query.raw", value: u.RawQuery}, {location: "url.query.decoded", value: multiDecode(u.RawQuery)}}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return out
	}
	for key, list := range values {
		out = append(out, sample{location: "query.name", value: key})
		for range list {
			out = append(out, sample{location: "query.value:" + key, value: strings.Join(list, " ")})
			break
		}
	}
	return out
}
func headerSamples(h http.Header) []sample {
	allowed := []string{"User-Agent", "Referer", "Content-Type", "X-Requested-With", "X-Original-URL", "X-Rewrite-URL"}
	out := make([]sample, 0, len(allowed))
	for _, name := range allowed {
		if v := h.Get(name); v != "" {
			out = append(out, sample{location: "header:" + strings.ToLower(name), value: v})
		}
	}
	return out
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
	}
	if truncated {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
	} else {
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
	}
	return inspect, truncated, nil
}
func multiDecode(value string) string {
	out := value
	for n := 0; n < 2; n++ {
		decoded, err := url.QueryUnescape(out)
		if err != nil || decoded == out {
			break
		}
		out = decoded
	}
	return out
}
func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
