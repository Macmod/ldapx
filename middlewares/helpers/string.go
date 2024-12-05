package helpers

import (
	"fmt"
	"math/rand"
	"strings"
)

func GenerateGarbageString(n int, chars string) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func HexEncodeChar(c rune) string {
	return fmt.Sprintf("\\%02x", c)
}

func RandomlyHexEncodeString(s string, prob float64) string {
	var result strings.Builder
	for _, c := range s {
		if rand.Float64() < prob {
			result.WriteString(HexEncodeChar(c))
		} else {
			result.WriteRune(c)
		}
	}

	return result.String()
}

func RandomlyChangeCaseString(s string, prob float64) string {
	var builder strings.Builder
	for _, c := range s {
		if rand.Float64() < prob {
			if rand.Intn(2) == 0 {
				builder.WriteString(strings.ToLower(string(c)))
			} else {
				builder.WriteString(strings.ToUpper(string(c)))
			}
		} else {
			builder.WriteRune(c)
		}
	}
	return builder.String()
}
