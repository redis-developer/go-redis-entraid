package entraid

import "time"

const (
	DefaultExpirationRefreshRatio        = 0.7
	DefaultRetryOptionsMaxAttempts       = 3
	DefaultRetryOptionsInitialDelayMs    = 1000
	DefaultRetryOptionsBackoffMultiplier = 2.0
	DefaultRetryOptionsMaxDelayMs        = 10000
	MinTokenTTL                          = 5 * time.Minute
)
