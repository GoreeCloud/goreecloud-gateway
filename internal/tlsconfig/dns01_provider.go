package tlsconfig

import "context"

const DNS01ProviderPorkbun = "porkbun"

// DNS01ChallengeRecord is provider-neutral cleanup state for one challenge
// record. It deliberately contains no credential or challenge value.
type DNS01ChallengeRecord struct {
	Provider string `json:"provider"`
	Zone     string `json:"zone"`
	Name     string `json:"name"`
	ID       string `json:"id"`
}

// DNS01Provider is the bounded DNS mutation boundary used by future ACME
// orchestration. Implementations may present and remove challenge TXT records;
// they are not general DNS management interfaces.
type DNS01Provider interface {
	Present(context.Context, string, string) (DNS01ChallengeRecord, error)
	Cleanup(context.Context, DNS01ChallengeRecord) error
}
