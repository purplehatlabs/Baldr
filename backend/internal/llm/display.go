package llm

// DisplayText returns the localized value when present, otherwise the English fallback.
func DisplayText(localized, fallback string) string {
	if localized != "" {
		return localized
	}
	return fallback
}
