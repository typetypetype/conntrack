package main

// Example usage

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/typetypetype/conntrack/ovs"
)

func main() {
	//cs, err := conntrack.Established()
	//if err != nil {
	//	panic(fmt.Sprintf("Established: %s", err))
	//}
	//fmt.Printf("Established on start:\n")
	//for _, cn := range cs {
	//	fmt.Printf(" - %s\n", cn)
	//}
	//fmt.Println("")
	//
	//c, err := conntrack.New()
	//if err != nil {
	//	panic(err)
	//}
	//for range time.Tick(1 * time.Second) {
	//	fmt.Printf("Connections:\n")
	//	for _, cn := range c.Connections() {
	//		fmt.Printf(" - %s\n", cn)
	//	}
	//}

	res, stopFunc, err := ovs.FollowOvsFlows(0, 0)

	if err != nil {
		panic(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		for flow := range res {
			fmt.Println(fmt.Sprintf("%+v", flow))
		}
	}()

	<-stop
	stopFunc()

}
