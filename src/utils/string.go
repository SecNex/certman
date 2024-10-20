package utils

import (
	"strings"
	"unicode"
)

func SanitizeString(input string) string {
	var result strings.Builder

	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
			result.WriteRune(unicode.ToLower(r))
		}
	}

	resultString := strings.ReplaceAll(result.String(), ".", "-")

	return resultString
}
