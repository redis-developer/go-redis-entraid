package entraid

import "fmt"

// ErrTokenManagerNotStarted is returned when the token manager is not started.
var ErrTokenManagerNotStarted = fmt.Errorf("token manager not started")

// ErrTokenManagerAlreadyCanceled is returned when the token manager is already canceled.
var ErrTokenManagerAlreadyCanceled = fmt.Errorf("token manager already canceled")

// ErrTokenManagerAlreadyStarted is returned when the token manager is already started.
var ErrTokenManagerAlreadyStarted = fmt.Errorf("token manager already started")
