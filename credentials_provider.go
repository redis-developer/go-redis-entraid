package entraid

import (
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9/auth"
)

// entraidCredentialsProvider implements the auth.StreamingCredentialsProvider interface.
var _ auth.StreamingCredentialsProvider = (*entraidCredentialsProvider)(nil)

// entraidCredentialsProvider is a struct that implements the CredentialProvider interface.
type entraidCredentialsProvider struct {
	options CredentialsProviderOptions

	tokenManager       TokenManager
	cancelTokenManager cancelFunc

	// listeners is a slice of listeners that are notified when the token manager receives a new token.
	listeners []auth.CredentialsListener

	// rwLock is a mutex that is used to synchronize access to the listeners slice.
	// It is used to ensure that only one goroutine can access the listeners slice at a time.
	rwLock sync.RWMutex
}

// onTokenNext is a method that is called when the token manager receives a new token.
func (e *entraidCredentialsProvider) onTokenNext(token *Token) {
	e.rwLock.RLock()
	defer e.rwLock.RUnlock()
	// Notify all listeners with the new token.
	for _, listener := range e.listeners {
		listener.OnNext(token)
	}
}

// onError is a method that is called when the token manager encounters an error.
// It notifies all listeners with the error.
func (e *entraidCredentialsProvider) onTokenError(err error) {
	e.rwLock.RLock()
	defer e.rwLock.RUnlock()
	// Notify all listeners with the error.
	for _, listener := range e.listeners {
		listener.OnError(err)
	}
}

// Subscribe subscribes to the credentials provider and returns a channel that will receive updates.
// The first response is blocking, then data will notify the listener.
// The listener will be notified with the credentials when they are available.
// The listener will be notified with an error if there is an error obtaining the credentials.
// The caller can cancel the subscription by calling the cancel function which is the second return value.
func (e *entraidCredentialsProvider) Subscribe(listener auth.CredentialsListener) (auth.Credentials, auth.CancelProviderFunc, error) {
	e.rwLock.Lock()
	// Check if the listener is already in the list of listeners.
	alreadySubscribed := false
	for _, l := range e.listeners {
		if l == listener {
			alreadySubscribed = true
			break
		}
	}

	if !alreadySubscribed {
		// Get the token from the identity provider.
		e.listeners = append(e.listeners, listener)
	}
	e.rwLock.Unlock()

	token, err := e.tokenManager.GetToken(false)
	if err != nil {
		go listener.OnError(err)
		return nil, nil, err
	}

	// Notify the listener with the credentials.
	go listener.OnNext(token)

	cancel := func() error {
		// Remove the listener from the list of listeners.
		e.rwLock.Lock()
		defer e.rwLock.Unlock()
		for i, l := range e.listeners {
			if l == listener {
				e.listeners = append(e.listeners[:i], e.listeners[i+1:]...)
				break
			}
		}
		if len(e.listeners) == 0 {
			if e.cancelTokenManager != nil {
				defer func() {
					e.cancelTokenManager = nil
					e.listeners = nil
				}()
				return e.cancelTokenManager()
			}
		}
		return nil
	}

	return token, cancel, nil
}

type entraidTokenListener struct {
	cp *entraidCredentialsProvider
}

func tokenListenerFromCP(cp *entraidCredentialsProvider) TokenListener {
	return &entraidTokenListener{
		cp,
	}
}

func (l *entraidTokenListener) OnTokenNext(token *Token) {
	l.cp.onTokenNext(token)
}

func (l *entraidTokenListener) OnTokenError(err error) {
	l.cp.onTokenError(err)
}

// newCredentialsProvider creates a new credentials provider.
// It takes a TokenManager and CredentialProviderOptions as arguments and returns a StreamingCredentialsProvider interface.
// The TokenManager is used to obtain the token, and the CredentialProviderOptions contains options for the credentials provider.
// The credentials provider is responsible for managing the credentials and refreshing them when necessary.
// It returns an error if the token manager cannot be started.
func newCredentialsProvider(tokenManager TokenManager, options CredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {
	cp := &entraidCredentialsProvider{
		tokenManager: tokenManager,
		options:      options,
	}
	cancelTokenManager, err := cp.tokenManager.Start(tokenListenerFromCP(cp))
	if err != nil {
		return nil, fmt.Errorf("couldn't start token manager: %w", err)
	}
	cp.cancelTokenManager = cancelTokenManager
	return cp, nil
}
