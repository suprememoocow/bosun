package adguard

// ValidTags is AdGuard Home's fixed client tag vocabulary. Tags outside this
// set make a client add/update call fail, so enrichment tags are validated
// against it at config-validation time (design doc §7.1).
var ValidTags = []string{
	"user_admin", "user_regular", "user_child",

	"device_audio", "device_camera", "device_gameconsole", "device_laptop",
	"device_nas", "device_pc", "device_phone", "device_printer", "device_router",
	"device_securityalarm", "device_tablet", "device_tv", "device_other",

	"os_android", "os_ios", "os_linux", "os_macos", "os_windows", "os_other",
}

var validTagSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(ValidTags))
	for _, t := range ValidTags {
		m[t] = struct{}{}
	}
	return m
}()

// ValidTag reports whether tag is part of AdGuard's fixed vocabulary.
func ValidTag(tag string) bool {
	_, ok := validTagSet[tag]
	return ok
}
