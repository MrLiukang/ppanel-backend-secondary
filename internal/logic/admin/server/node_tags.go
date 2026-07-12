package server

import "strings"

func normalizeNodeTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}

	tags := make([]string, 0)
	for _, tag := range strings.Split(raw, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}
