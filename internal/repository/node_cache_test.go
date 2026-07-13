package repository

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestClearServerCacheDoesNotDependOnExistingNodes(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	for _, key := range []string{"server:user:77", "server:user:77:vless", "server:config:77:vless", "server:user:88:vless"} {
		if err := client.Set(ctx, key, "cached", 0).Err(); err != nil {
			t.Fatal(err)
		}
	}
	repo := &nodeRepo{Cache: client}
	if err := repo.ClearServerCache(ctx, 77); err != nil {
		t.Fatalf("ClearServerCache() error = %v", err)
	}
	for _, key := range []string{"server:user:77", "server:user:77:vless", "server:config:77:vless"} {
		if mr.Exists(key) {
			t.Fatalf("server cache key %q remains after direct serverID clear", key)
		}
	}
	if !mr.Exists("server:user:88:vless") {
		t.Fatal("another server's cache was deleted")
	}
}
