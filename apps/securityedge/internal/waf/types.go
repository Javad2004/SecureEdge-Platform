package waf

type Match struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Category    string `json:"category"`
	Score       int    `json:"score"`
	Target      string `json:"target"`
	Location    string `json:"location"`
	Fingerprint string `json:"fingerprint"`
}

type Result struct {
	Score             int     `json:"score"`
	Matches           []Match `json:"matches"`
	BodyInspected     bool    `json:"body_inspected"`
	BodyTruncated     bool    `json:"body_truncated"`
	Excluded          bool    `json:"excluded"`
	MatchLimitReached bool    `json:"match_limit_reached"`
}
