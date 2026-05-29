package i18n

import "testing"

func TestParseLocale(t *testing.T) {
	tests := map[string]string{
		"en":    LocaleEN,
		"EN":    LocaleEN,
		"pt-BR": LocalePtBR,
		"pt-br": LocalePtBR,
		"pt_br": LocalePtBR,
		"":      LocaleEN,
	}
	for input, want := range tests {
		if got := ParseLocale(input); got != want {
			t.Fatalf("ParseLocale(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveDisplayText(t *testing.T) {
	en := "english"
	pt := "portuguese"

	enPtr := &en
	ptPtr := &pt

	if got := ResolveDisplayText(LocalePtBR, enPtr, ptPtr); got == nil || *got != pt {
		t.Fatalf("expected pt-BR text")
	}
	if got := ResolveDisplayText(LocaleEN, enPtr, ptPtr); got == nil || *got != en {
		t.Fatalf("expected EN text")
	}
	if got := ResolveDisplayText(LocalePtBR, enPtr, nil); got == nil || *got != en {
		t.Fatalf("expected EN fallback for pt-BR")
	}
}
