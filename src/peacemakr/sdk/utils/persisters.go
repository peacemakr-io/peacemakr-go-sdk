package utils

import (
	"github.com/patrickmn/go-cache"
	"time"
)

type Persister interface {
	Save(key, value string) error
	Load(key string) (string, error)
	Exists(key string) bool
}

func GetDiskPersister(path string) Persister {
	id, err := GetRandomIdentifier()
	if err != nil {
		id = ""
	}

	// Create a cache with a default expiration time of 5 minutes, and which
	// purges expired items every 10 minutes
	c := cache.New(5*time.Minute, 10*time.Minute)

	fileP := &filePersister{
		path,
		c,
		id,
	}
	return Persister(fileP)
}
