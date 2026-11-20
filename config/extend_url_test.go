package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remoteRuleLibrary serves the given TOML payload and counts how many requests
// the config loader made. Everything stays on loopback so the tests run in a
// snapshot environment with no external dependency.
func remoteRuleLibrary(t *testing.T, payload string) (url string, requests *atomic.Int64) {
	t.Helper()
	requests = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/toml")
		_, _ = fmt.Fprint(w, payload)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, requests
}

// loadThinConfig parses a local "thin" config the same way the CLI does: read
// the TOML, unmarshal it into ViperConfig, then Translate. This keeps the test
// on the production parsing and validation pipeline.
func loadThinConfig(t *testing.T, content string) (Config, error) {
	t.Helper()
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})
	viper.Reset()
	// extendDepth is a package-level global; earlier tests in this package may
	// leave it non-zero (they only reset viper). Start from a clean depth.
	extendDepth = 0
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(content)); err != nil {
		t.Fatalf("failed to read thin config: %v", err)
	}
	var vc ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		t.Fatalf("failed to unmarshal thin config: %v", err)
	}
	return vc.Translate()
}

const remoteLibraryTOML = `
title = "managed credential rules"

[[rules]]
id = "managed-credential-rule"
description = "Managed credential rule"
regex = '''managed_tok_[A-Za-z0-9]{16}'''
keywords = ["managed_tok_"]
`

const thinLocalRuleTOML = `
[[rules]]
id = "local-thin-rule"
description = "Local thin rule"
regex = '''local_tok_[A-Za-z0-9]{16}'''
`

// TestExtendURLChannelMatrix covers the four-row input matrix derived from the
// extension channel clause.
func TestExtendURLChannelMatrix(t *testing.T) {
	t.Run("url only merges remote rules alongside the local rule", func(t *testing.T) {
		serverURL, requests := remoteRuleLibrary(t, remoteLibraryTOML)

		cfg, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.NoError(t, err)

		_, hasLocal := cfg.Rules["local-thin-rule"]
		_, hasRemote := cfg.Rules["managed-credential-rule"]
		t.Logf("readings: managed_requests=%d local_rule_present=%t remote_rule_present=%t ruleset_size=%d",
			requests.Load(), hasLocal, hasRemote, len(cfg.Rules))
		assert.Greater(t, requests.Load(), int64(0), "managed rule library must be queried")
		assert.True(t, hasLocal, "local rule must be present")
		assert.True(t, hasRemote, "remote rule must be merged into the ruleset")
		assert.Contains(t, cfg.Keywords, "managed_tok_")
	})

	t.Run("url plus useDefault is rejected before any fetch", func(t *testing.T) {
		serverURL, requests := remoteRuleLibrary(t, remoteLibraryTOML)

		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
useDefault = true
%s`, serverURL, thinLocalRuleTOML))
		require.Error(t, err)
		t.Logf("readings: managed_requests=%d load_failed=%t error=%q", requests.Load(), err != nil, err)
		assert.Contains(t, err.Error(), "extend.url")
		assert.Contains(t, err.Error(), "extend.useDefault")
		assert.Contains(t, err.Error(), "mutually exclusive")
		assert.Equal(t, int64(0), requests.Load(), "rejected combination must not silently fall back to default rules")
	})

	t.Run("url plus path is rejected before any fetch", func(t *testing.T) {
		serverURL, requests := remoteRuleLibrary(t, remoteLibraryTOML)

		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
path = "../testdata/config/valid/extend_base_3.toml"
%s`, serverURL, thinLocalRuleTOML))
		require.Error(t, err)
		t.Logf("readings: managed_requests=%d load_failed=%t error=%q", requests.Load(), err != nil, err)
		assert.Contains(t, err.Error(), "extend.url")
		assert.Contains(t, err.Error(), "extend.path")
		assert.Contains(t, err.Error(), "mutually exclusive")
		assert.Equal(t, int64(0), requests.Load())
	})

	t.Run("unreachable url fails visibly", func(t *testing.T) {
		// Bind a port, then close it so nothing is listening when we fetch.
		dead := httptest.NewServer(http.NotFoundHandler())
		deadURL := dead.URL
		dead.Close()

		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, deadURL, thinLocalRuleTOML))
		require.Error(t, err, "an unreachable managed rule library must surface as a load failure")
		t.Logf("readings: load_failed=%t error=%q", err != nil, err)
		assert.Contains(t, err.Error(), deadURL)
		assert.Contains(t, err.Error(), "failed to fetch extended config")
	})
}

// TestExtendURLUsesSharedPipeline verifies that remote content is parsed and
// validated by the same code path as a local extended config, including the
// nested extend depth limit and rule validation.
func TestExtendURLUsesSharedPipeline(t *testing.T) {
	t.Run("invalid rule in remote content fails", func(t *testing.T) {
		serverURL, _ := remoteRuleLibrary(t, `
[[rules]]
id = "no-matcher"
description = "missing both regex and path"
`)
		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both |regex| and |path| are empty")
	})

	t.Run("invalid toml in remote content fails", func(t *testing.T) {
		serverURL, _ := remoteRuleLibrary(t, "this is not toml = = =")
		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.Error(t, err)
	})

	t.Run("empty remote content fails instead of silently merging nothing", func(t *testing.T) {
		serverURL, _ := remoteRuleLibrary(t, "   \n")
		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("nested extend depth limit applies to remote content", func(t *testing.T) {
		// Remote ruleset itself extends a local fixture one hop away, so the
		// chain is root -> remote -> path. The depth limit must still cap it.
		serverURL, _ := remoteRuleLibrary(t, `
[extend]
path = "../testdata/config/valid/extend_base_3.toml"

[[rules]]
id = "managed-credential-rule"
regex = '''managed_tok_[A-Za-z0-9]{16}'''
`)
		cfg, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.NoError(t, err)
		// One hop from the remote ruleset is still allowed.
		_, ok := cfg.Rules["aws-secret-key-again-again"]
		assert.True(t, ok, "nested extend from remote content should be honored within the depth limit")
	})

	t.Run("nested extend beyond the depth limit is capped", func(t *testing.T) {
		// root -> remote -> base_1 -> base_2 would be depth 3, which exceeds
		// maxExtendDepth. Only root -> remote -> base_1 is loaded.
		serverURL, _ := remoteRuleLibrary(t, `
[extend]
path = "../testdata/config/valid/extend_base_1.toml"

[[rules]]
id = "managed-credential-rule"
regex = '''managed_tok_[A-Za-z0-9]{16}'''
`)
		cfg, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, serverURL, thinLocalRuleTOML))
		require.NoError(t, err)
		_, hasBase1 := cfg.Rules["aws-access-key"]
		_, hasBase2 := cfg.Rules["aws-secret-key-again"]
		assert.True(t, hasBase1, "first nested hop must load")
		assert.False(t, hasBase2, "second nested hop must be cut off by the depth limit")
	})

	t.Run("non-2xx response fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "managed registry unavailable", http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)

		_, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q
%s`, srv.URL, thinLocalRuleTOML))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected HTTP status")
	})

	t.Run("duplicate rule id keeps local override semantics", func(t *testing.T) {
		serverURL, _ := remoteRuleLibrary(t, `
[[rules]]
id = "shared-rule"
description = "Remote description"
regex = '''shared_tok_[A-Za-z0-9]{16}'''
tags = ["remote"]

[[rules]]
id = "remote-only-rule"
regex = '''remote_only_[A-Za-z0-9]{16}'''
`)
		cfg, err := loadThinConfig(t, fmt.Sprintf(`
[extend]
url = %q

[[rules]]
id = "shared-rule"
description = "Local description"
`, serverURL))
		require.NoError(t, err)

		shared := cfg.Rules["shared-rule"]
		assert.Equal(t, "Local description", shared.Description, "local attributes override the remote rule")
		assert.NotNil(t, shared.Regex, "unchanged remote attributes are inherited")
		_, ok := cfg.Rules["remote-only-rule"]
		assert.True(t, ok, "remote-only rule is appended")
	})
}
