package buildinfo

import (
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/licensing"
)

func TestOfficialBuildTrustIncludesLeaseAndArtifactKeys(t *testing.T) {
	for _, purpose := range []string{licensing.KeyPurposeLease, licensing.KeyPurposeArtifact} {
		keys, err := licensing.CertifiedTrustedKeys(RootPublicKey, SignedKeySet, purpose, time.Now())
		if err != nil || len(keys) == 0 {
			t.Fatalf("official %s trust unavailable: %v", purpose, err)
		}
	}
}
