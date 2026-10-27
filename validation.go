package rbac

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Catalog IDs use lowercase names with optional namespace separators.
func validID(value string) bool {
	if len(value) == 0 || value[0] < 'a' || value[0] > 'z' {
		return false
	}

	separator := false

	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' {
			separator = false

			continue
		}

		if separator || !strings.ContainsRune("._:-", character) {
			return false
		}

		separator = true
	}

	return !separator
}

func validText(value string) bool {
	if value == "" || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}

	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}

	return true
}
