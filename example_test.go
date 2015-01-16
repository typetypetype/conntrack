package conntrack_test

// Example usage

import (
	"fmt"
	"time"

	"github.com/typetypetype/conntrack"
)

func main() {
	c, err := conntrack.New()
	if err != nil {
		panic(err)
	}
	for range time.Tick(1 * time.Second) {
		fmt.Printf("Connections:\n")
		for _, cn := range c.Connections() {
			fmt.Printf(" - %s\n", cn)
		}
	}
}
