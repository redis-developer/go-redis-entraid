package examples_test

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func ExampleEstablishRedisConn() {
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs: []string{"localhost:6379"},
	})
	fmt.Println(rdb.Ping(context.Background()).String())
	// Output: ping: PONG
}
