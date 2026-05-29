package i18n

import (
	"strings"
)

const (
	LocaleEN         = "en"
	LocalePtBR       = "pt-BR"
	DefaultLocale    = LocaleEN
	HeaderAcceptLang = "Accept-Language"
)

func ParseLocale(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pt-br", "pt_br", "ptbr":
		return LocalePtBR
	default:
		return LocaleEN
	}
}

func IsPtBR(locale string) bool {
	return ParseLocale(locale) == LocalePtBR
}

func ResolveDisplayText(locale string, original, localized *string) *string {
	if IsPtBR(locale) {
		return firstNonEmptyPtr(localized, original)
	}
	return firstNonEmptyPtr(original)
}

func firstNonEmptyPtr(values ...*string) *string {
	for _, v := range values {
		if v != nil && *v != "" {
			return v
		}
	}
	return nil
}
