package llm

import "testing"

func TestResolveModelForAuthRemapsRetiredCodexModels(t *testing.T) {
	got, remapped, reason := ResolveModelForAuth(AuthModeCodexOAuth, "gpt-5.3-codex", "gpt-6.1-sol", "")
	if !remapped || got != "gpt-6.1-sol" || reason == "" {
		t.Fatalf("got=%s remapped=%v reason=%q", got, remapped, reason)
	}
	api, remapped, _ := ResolveModelForAuth(AuthModeAPIKey, "gpt-4o", "", "")
	if remapped || api != "gpt-4o" {
		t.Fatalf("api-key path remapped unexpectedly: %s %v", api, remapped)
	}
}

func TestSelectProviderHonorsExplicitPreference(t *testing.T) {
	_, _, err := SelectProvider(SelectionInput{
		Preference:     ProviderCodex,
		CodexAvailable: false,
		Model:          "gpt-6.1-sol",
	})
	if err == nil {
		t.Fatal("expected missing Codex login to fail")
	}

	p, sel, err := SelectProvider(SelectionInput{
		Preference:     ProviderAPIKey,
		APIKey:         "sk-test",
		Model:          "gpt-4o",
		CodexAvailable: true,
	})
	if err != nil || p == nil || sel.Source != "api_key" || sel.Model != "gpt-4o" {
		t.Fatalf("api key preference failed: %+v %v", sel, err)
	}
}

func TestIsPermanentModelError(t *testing.T) {
	err := &permanentStub{msg: `codex API error (HTTP 400): {"detail":"The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account."}`}
	if !IsPermanentModelError(err) {
		t.Fatal("expected permanent model error")
	}
	if IsPermanentModelError(&permanentStub{msg: "connection refused"}) {
		t.Fatal("transient error misclassified")
	}
}

type permanentStub struct{ msg string }

func (p *permanentStub) Error() string { return p.msg }
