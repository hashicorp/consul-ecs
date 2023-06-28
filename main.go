// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/hashicorp/consul-ecs/version"
	"github.com/mitchellh/cli"
)

func main() {
	c := cli.NewCLI("consul-ecs", version.GetHumanVersion())
	c.Args = os.Args[1:]
	c.Commands = Commands
	c.HelpFunc = helpFunc()

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	os.Exit(exitStatus)
}

// You can edit this code!
// Click here and start typing.
// package main

// import (
// 	"fmt"
// )

// func main() {
// 	ch1 := make(chan int, 1)
// 	ch2 := make(chan int, 1)
// 	ans := make([]int, 0)
// 	var v1, v2 int

// 	//var ansLock sync.RWMutex

// 	maxAnsLen := 1000

// 	go func() {
// 		var i int
// 		for i = 1; i <= 500; i++ {
// 			ch1 <- i
// 		}
// 	}()

// 	go func() {
// 		var i int
// 		for i = 501; i <= maxAnsLen; i++ {
// 			ch2 <- i
// 		}
// 	}()

// 	for {
// 		select {
// 		case v1 = <-ch1:
// 			//ansLock.Lock()
// 			ans = append(ans, v1)
// 			for _, v := range ans {
// 				fmt.Printf("%d ", v)
// 			}
// 			fmt.Println()
// 			if len(ans) == maxAnsLen {
// 				return
// 			}
// 			//ansLock.Unlock()
// 		case v2 = <-ch2:
// 			//ansLock.Lock()
// 			ans = append(ans, v2)
// 			for _, v := range ans {
// 				fmt.Printf("%d ", v)
// 			}
// 			fmt.Println()
// 			if len(ans) == maxAnsLen {
// 				return
// 			}
// 			//ansLock.Unlock()
// 		}
// 	}
// }
