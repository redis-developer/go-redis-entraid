package entraid

const (
	DefaultExpirationRefreshRatio        = 0.7
	DefaultRetryOptionsMaxAttempts       = 3
	DefaultRetryOptionsInitialDelayMs    = 1000
	DefaultRetryOptionsBackoffMultiplier = 2.0
	DefaultRetryOptionsMaxDelayMs        = 10000
	MinTokenTTL                          = 60 * 1000 // 1 minute
)
