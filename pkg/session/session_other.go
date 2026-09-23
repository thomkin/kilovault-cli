//go:build !linux

package session

import "time"

func Save(id string, key []byte, ttl time.Duration) (time.Time, error) {
	return time.Time{}, ErrUnavailable
}

func Load(id string) (*Session, error) {
	return nil, nil
}

func Clear(id string) (bool, error) {
	return false, nil
}
