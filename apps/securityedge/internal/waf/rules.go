package waf

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
)

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Score       int      `json:"score"`
	Targets     []string `json:"targets"`
	Source      string   `json:"source"`
	pattern     *regexp.Regexp
}

func BuiltinRules() []Rule {
	type spec struct {
		id, name, category, description, pattern string
		score                                    int
		targets                                  []string
	}
	specs := []spec{
		{"SQLI-001", "UNION SELECT", "sqli", "Detects common SQL UNION-based injection syntax.", `(?i)\bunion(?:\s+all)?\s+select\b`, 5, []string{"path", "query", "body"}},
		{"SQLI-002", "Boolean tautology", "sqli", "Detects SQL boolean expressions commonly used to bypass authentication.", `(?i)(?:'|\"|` + "`" + `)?\s*(?:or|and)\s+(?:\d+|'[^']*')\s*=\s*(?:\d+|'[^']*')`, 5, []string{"query", "body"}},
		{"SQLI-003", "Time-based SQLi", "sqli", "Detects database delay functions used for blind SQL injection.", `(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b`, 5, []string{"query", "body"}},
		{"SQLI-004", "SQL metadata access", "sqli", "Detects access to common database metadata tables.", `(?i)\b(?:information_schema|pg_catalog|sqlite_master|sysobjects|syscolumns)\b`, 4, []string{"query", "body"}},
		{"SQLI-005", "Stacked SQL statement", "sqli", "Detects statement separators followed by destructive or administrative SQL commands.", `(?i);\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec(?:ute)?)\b`, 5, []string{"query", "body"}},
		{"SQLI-006", "SQL comment bypass", "sqli", "Detects SQL comment syntax commonly used to terminate or obfuscate injected clauses.", `(?i)(?:--(?:\s|$)|/\*![0-9]*|/\*[^*]{0,200}\*/|#[^\r\n]{0,200})`, 3, []string{"query", "body"}},
		{"SQLI-007", "SQL file operations", "sqli", "Detects database file read/write primitives.", `(?i)\b(?:load_file|into\s+outfile|into\s+dumpfile|xp_cmdshell)\b`, 5, []string{"query", "body"}},
		{"XSS-001", "Script tag", "xss", "Detects injected script elements.", `(?i)<\s*/?\s*script\b`, 5, []string{"path", "query", "body"}},
		{"XSS-002", "Event handler", "xss", "Detects inline browser event handlers often used for XSS.", `(?i)\bon(?:error|load|click|mouseover|focus|animationstart|pointerover|toggle)\s*=`, 4, []string{"query", "body"}},
		{"XSS-003", "JavaScript URI", "xss", "Detects javascript: and vbscript: URI payloads.", `(?i)(?:javascript|vbscript)\s*:`, 5, []string{"path", "query", "body", "headers"}},
		{"XSS-004", "Dangerous HTML element", "xss", "Detects iframe, object, embed, svg, and math elements frequently used in XSS payloads.", `(?i)<\s*(?:iframe|object|embed|svg|math|meta|base)\b`, 4, []string{"query", "body"}},
		{"XSS-005", "Data URI script", "xss", "Detects executable HTML or SVG data URIs.", `(?i)data\s*:\s*(?:text/html|image/svg\+xml)[^,]{0,200},`, 5, []string{"query", "body", "headers"}},
		{"PATH-001", "Path traversal", "path_traversal", "Detects plain or encoded parent-directory traversal.", `(?i)(?:\.\.[/\\]|%2e%2e(?:%2f|%5c|[/\\])|%252e%252e)`, 5, []string{"path", "query", "body"}},
		{"PATH-002", "Sensitive file probe", "recon", "Detects requests for commonly exposed secrets and system files.", `(?i)(?:^|[/\\])(?:\.env|\.git(?:[/\\]|$)|wp-config\.php|etc[/\\]passwd|etc[/\\]shadow|id_rsa|web\.config|application\.properties)(?:$|[/\\?])`, 4, []string{"path", "query"}},
		{"PATH-003", "Windows device path", "path_traversal", "Detects Windows device and UNC paths.", `(?i)(?:\\\\\.\\|\\\\\?\\|\\\\[^\\/]+\\[^\\/]+|\b(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\b)`, 4, []string{"path", "query", "body"}},
		{"CMD-001", "Command separator", "command_injection", "Detects shell separators followed by common operating-system commands.", `(?i)(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|powershell|cmd|nc|netcat|python|perl|ruby)\b`, 5, []string{"query", "body"}},
		{"CMD-002", "Command substitution", "command_injection", "Detects shell command substitution syntax.", `(?s)(?:\$\([^)]{1,300}\)|` + "`[^`]{1,300}`" + `)`, 5, []string{"query", "body"}},
		{"CMD-003", "Environment variable expansion", "command_injection", "Detects suspicious shell and Windows environment variable expansion.", `(?i)(?:\$\{(?:IFS|PATH|HOME|SHELL)[^}]*\}|%(?:COMSPEC|PATH|TEMP|WINDIR)%)`, 4, []string{"query", "body"}},
		{"SSRF-001", "Cloud metadata endpoint", "ssrf", "Detects access attempts to common cloud instance metadata services.", `(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)(?::\d+)?`, 5, []string{"query", "body"}},
		{"SSRF-002", "Local network target", "ssrf", "Detects URL parameters targeting loopback, unspecified, or private network services.", `(?i)(?:https?|ftp|gopher|file)://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})`, 4, []string{"query", "body"}},
		{"XXE-001", "XML external entity", "xxe", "Detects XML external entity and external DTD declarations.", `(?is)<!DOCTYPE[^>]{0,500}(?:SYSTEM|PUBLIC)|<!ENTITY[^>]{0,500}(?:SYSTEM|PUBLIC)`, 5, []string{"body"}},
		{"NOSQL-001", "NoSQL operator injection", "nosqli", "Detects common MongoDB-style query operators.", `(?i)(?:\$where|\$ne|\$gt|\$gte|\$lt|\$lte|\$regex|\$nin)\s*(?:\]|\}|:|=)`, 4, []string{"query", "body"}},
		{"LDAP-001", "LDAP filter injection", "ldap_injection", "Detects suspicious LDAP filter operators and wildcard constructs.", `(?i)(?:\(\|\(|\(&\(|\)\(\||\*\)\(|\x00)`, 4, []string{"query", "body"}},
		{"CRLF-001", "CRLF injection", "protocol", "Detects encoded or literal CRLF sequences in request targets.", `(?i)(?:%0d%0a|%0a|%0d|\r\n)`, 4, []string{"path", "query"}},
		{"PROTO-001", "Template expression", "template_injection", "Detects common server-side template expression delimiters.", `(?:\{\{[^{}]{0,200}\}\}|\$\{[^{}]{0,200}\}|<%[^%]{0,200}%>)`, 4, []string{"query", "body"}},
		{"PROTO-002", "JNDI lookup", "rce", "Detects Log4Shell-style JNDI lookup expressions.", `(?i)\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http)\s*:`, 5, []string{"path", "query", "body", "headers"}},
		{"PROTO-003", "PHP wrapper", "rce", "Detects PHP stream wrappers frequently used for local/remote file inclusion.", `(?i)\b(?:php|data|expect|zip|phar|glob|input)://`, 5, []string{"path", "query", "body"}},
		{"PROTO-004", "Null byte", "protocol", "Detects encoded or literal null bytes used to confuse path and parser handling.", `(?i)(?:%00|\x00)`, 4, []string{"path", "query", "body"}},
		{"SCAN-001", "Security scanner user agent", "recon", "Detects common automated vulnerability scanner identifiers.", `(?i)\b(?:sqlmap|nikto|acunetix|nessus|nmap|masscan|dirbuster|gobuster|ffuf|wpscan|zgrab)\b`, 3, []string{"headers"}},
		{"SCAN-002", "Exploit framework marker", "recon", "Detects common exploit framework and payload generator markers.", `(?i)\b(?:metasploit|meterpreter|commix|nuclei|burp(?:suite)?|owasp\s*zap)\b`, 3, []string{"headers", "query", "body"}},
		{"REDIR-001", "Protocol-relative redirect", "open_redirect", "Detects redirect-like parameters containing protocol-relative external targets.", `(?i)(?:^|[?&])(?:url|uri|redirect|return|next|continue|dest(?:ination)?)=\s*(?:%2f%2f|//)`, 3, []string{"query"}},
		{"COOKIE-001", "Cookie injection", "protocol", "Detects control characters or response-splitting syntax in cookie values.", `(?i)(?:%0d|%0a|\r|\n|;\s*(?:httponly|secure|samesite)\s*=)`, 4, []string{"cookies"}},
	}
	out := make([]Rule, 0, len(specs))
	for _, s := range specs {
		out = append(out, Rule{ID: s.id, Name: s.name, Category: s.category, Description: s.description, Score: s.score, Targets: s.targets, Source: "builtin", pattern: regexp.MustCompile(s.pattern)})
	}
	return out
}

func CompileRules(custom []config.CustomRuleConfig) ([]Rule, error) {
	out := BuiltinRules()
	seen := make(map[string]bool, len(out)+len(custom))
	for _, r := range out {
		seen[r.ID] = true
	}
	for _, c := range custom {
		id := strings.ToUpper(strings.TrimSpace(c.ID))
		if seen[id] {
			return nil, fmt.Errorf("duplicate WAF rule ID %q", id)
		}
		compiled, err := regexp.Compile(c.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile custom rule %s: %w", id, err)
		}
		targets := make([]string, 0, len(c.Targets))
		for _, target := range c.Targets {
			targets = append(targets, strings.ToLower(strings.TrimSpace(target)))
		}
		out = append(out, Rule{ID: id, Name: c.Name, Category: strings.ToLower(c.Category), Description: c.Description, Score: c.Score, Targets: targets, Source: "custom", pattern: compiled})
		seen[id] = true
	}
	return out, nil
}
