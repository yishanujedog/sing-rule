package constant

import (
	"strings"

	"github.com/sagernet/srsc/common/semver"
)

type Platform string

const (
	PlatformUnknown Platform = ""
	PlatformSingBox Platform = "sing-box"
)

type System string

const (
	SystemUnknown   System = ""
	SystemAndroid   System = "android"
	SystemiOS       System = "ios"
	SystemMacOS     System = "macos"
	SystemAppleTVOS System = "tvos"
)

type Metadata struct {
	UserAgent string
	Platform  Platform
	System    System
	Version   *semver.Version
}

var systemPrefixes = [...]struct {
	prefix string
	system System
}{
	{"SFA", SystemAndroid},
	{"SFI", SystemiOS},
	{"SFM", SystemMacOS},
	{"SFT", SystemAppleTVOS},
}

func DetectMetadata(userAgent string) Metadata {
	metadata := Metadata{UserAgent: userAgent}
	metadata.System = detectSystem(userAgent)
	platform, version := detectSingBoxPlatform(userAgent)
	if platform != PlatformUnknown {
		metadata.Platform = platform
		metadata.Version = version
	}
	return metadata
}

func detectSystem(userAgent string) System {
	for _, candidate := range systemPrefixes {
		if strings.HasPrefix(userAgent, candidate.prefix) {
			return candidate.system
		}
	}
	return SystemUnknown
}

func detectSingBoxPlatform(userAgent string) (Platform, *semver.Version) {
	if versionRaw, ok := extractVersionSegment(userAgent, "sing-box "); ok {
		return PlatformSingBox, parseSemver(versionRaw)
	}
	if versionRaw, ok := extractVersionSegment(userAgent, "sing-box/"); ok {
		return PlatformSingBox, parseSemver(versionRaw)
	}
	return PlatformUnknown, nil
}

func extractVersionSegment(userAgent, marker string) (string, bool) {
	idx := strings.Index(userAgent, marker)
	if idx == -1 {
		return "", false
	}
	remainder := userAgent[idx+len(marker):]
	trimmed := trimAtFirstDelimiter(remainder)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func trimAtFirstDelimiter(source string) string {
	end := len(source)
	for _, delimiter := range []string{";", ")"} {
		if idx := strings.Index(source, delimiter); idx >= 0 && idx < end {
			end = idx
		}
	}
	return strings.TrimSpace(source[:end])
}

func parseSemver(version string) *semver.Version {
	if version == "" || !semver.IsValid(version) {
		return nil
	}
	parsed := semver.ParseVersion(version)
	return &parsed
}
