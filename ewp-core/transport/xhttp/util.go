package xhttp

import "time"

func generatePadding(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[int(time.Now().UnixNano()+int64(i))%len(chars)]
	}
	return string(result)
}
