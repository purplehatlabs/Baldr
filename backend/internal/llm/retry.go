package llm

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"
)

const (
	defaultMaxRetries = 4
	defaultRetryBase  = 500 * time.Millisecond
	defaultRetryMax   = 8 * time.Second
)

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Network timeouts and temporary failures from http.Client.
	return true
}

func retryDelay(attempt int) time.Duration {
	delay := time.Duration(float64(defaultRetryBase) * math.Pow(2, float64(attempt)))
	if delay > defaultRetryMax {
		return defaultRetryMax
	}
	return delay
}

func doChatCompletionWithRetry(ctx context.Context, httpClient *http.Client, req *http.Request) ([]byte, int, error) {
	var lastErr error
	var lastStatus int
	var lastBody []byte

	for attempt := 0; attempt < defaultMaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, lastStatus, ctx.Err()
			case <-time.After(retryDelay(attempt - 1)):
			}
		}

		body, status, err := doChatCompletion(httpClient, req)
		lastBody, lastStatus, lastErr = body, status, err

		if err != nil {
			if !isRetryableError(err) || attempt == defaultMaxRetries-1 {
				return nil, status, err
			}
			continue
		}
		if status < 400 {
			return body, status, nil
		}
		if !isRetryableStatus(status) || attempt == defaultMaxRetries-1 {
			return body, status, fmt.Errorf("litellm returned %d: %s", status, truncate(string(body), 500))
		}
	}

	if lastErr != nil {
		return nil, lastStatus, lastErr
	}
	return lastBody, lastStatus, fmt.Errorf("litellm returned %d: %s", lastStatus, truncate(string(lastBody), 500))
}
