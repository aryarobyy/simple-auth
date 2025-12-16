package helper

func IsValidName(s string) bool {
	if s == "" {
		return false
	}

	for _, ch := range s {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == ' ') {
			return false
		}
	}
	return true
}
