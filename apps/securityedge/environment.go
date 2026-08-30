package securityedge

import "github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/envfile"

// LoadEnvironmentFile loads SecurityEdge dotenv values using SecurityEdge's
// own managed-environment state. Embedders should use this helper instead of a
// host application's dotenv loader so later host-environment reloads cannot
// unset SecurityEdge-owned variables.
func LoadEnvironmentFile(explicit string, candidates ...string) (string, error) {
	return envfile.Load(explicit, candidates...)
}
