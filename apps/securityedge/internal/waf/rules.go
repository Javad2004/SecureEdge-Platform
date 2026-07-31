package waf

import "regexp"

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Score       int      `json:"score"`
	Targets     []string `json:"targets"`
	pattern     *regexp.Regexp
}

func BuiltinRules() []Rule {
	specs := []struct {
		id, name, category, description, pattern string
		score                                    int
		targets                                  []string
	}{
		{"SQLI-001", "UNION SELECT", "sqli", "Detects common SQL UNION-based injection syntax.", `(?i)\bunion(?:\s+all)?\s+select\b`, 5, []string{"path", "query", "body"}},
		{"SQLI-002", "Boolean tautology", "sqli", "Detects SQL boolean expressions commonly used to bypass authentication.", `(?i)(?:'|\"|` + "`" + `)?\s*(?:or|and)\s+(?:\d+|'[^']*')\s*=\s*(?:\d+|'[^']*')`, 5, []string{"query", "body"}},
		{"SQLI-003", "Time-based SQLi", "sqli", "Detects database delay functions used for blind SQL injection.", `(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b`, 5, []string{"query", "body"}},
		{"SQLI-004", "SQL metadata access", "sqli", "Detects access to common database metadata tables.", `(?i)\b(?:information_schema|pg_catalog|sqlite_master)\b`, 4, []string{"query", "body"}},
		{"XSS-001", "Script tag", "xss", "Detects injected script elements.", `(?i)<\s*/?\s*script\b`, 5, []string{"path", "query", "body"}},
		{"XSS-002", "Event handler", "xss", "Detects inline browser event handlers often used for XSS.", `(?i)\bon(?:error|load|click|mouseover|focus|animationstart)\s*=`, 4, []string{"query", "body"}},
		{"XSS-003", "JavaScript URI", "xss", "Detects javascript: URI payloads.", `(?i)javascript\s*:`, 5, []string{"path", "query", "body", "headers"}},
		{"PATH-001", "Path traversal", "path_traversal", "Detects plain or encoded parent-directory traversal.", `(?i)(?:\.\.[/\\]|%2e%2e(?:%2f|%5c|[/\\])|%252e%252e)`, 5, []string{"path", "query", "body"}},
		{"PATH-002", "Sensitive file probe", "recon", "Detects requests for commonly exposed secrets and system files.", `(?i)(?:^|[/\\])(?:\.env|\.git(?:[/\\]|$)|wp-config\.php|etc[/\\]passwd|id_rsa)(?:$|[/\\?])`, 4, []string{"path", "query"}},
		{"CMD-001", "Command separator", "command_injection", "Detects shell separators followed by common operating-system commands.", `(?i)(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|powershell|cmd|nc|netcat)\b`, 5, []string{"query", "body"}},
		{"CRLF-001", "CRLF injection", "protocol", "Detects encoded or literal CRLF sequences in request targets.", `(?i)(?:%0d%0a|%0a|%0d|\r\n)`, 4, []string{"path", "query"}},
		{"SCAN-001", "Security scanner user agent", "recon", "Detects common automated vulnerability scanner identifiers.", `(?i)\b(?:sqlmap|nikto|acunetix|nessus|nmap|masscan|dirbuster|gobuster)\b`, 3, []string{"headers"}},
		{"PROTO-001", "Template expression", "template_injection", "Detects common server-side template expression delimiters.", `(?:\{\{[^{}]{0,200}\}\}|\$\{[^{}]{0,200}\}|<%[^%]{0,200}%>)`, 4, []string{"query", "body"}},
	}
	out := make([]Rule, 0, len(specs))
	for _, s := range specs {
		out = append(out, Rule{ID: s.id, Name: s.name, Category: s.category, Description: s.description, Score: s.score, Targets: s.targets, pattern: regexp.MustCompile(s.pattern)})
	}
	return out
}
