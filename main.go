package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("hello")
		app, err := InitializeApp()
		if err != nil {
			log.Panic(err)
		}
		//     gracefulStop start
		var gracefulStop = make(chan os.Signal)
		signal.Notify(gracefulStop, syscall.SIGTERM)
		signal.Notify(gracefulStop, syscall.SIGINT)
		go func() {
			sig := <-gracefulStop
			fmt.Printf("caught term sig: %+v", sig)
			app.Stop()
			os.Exit(0)
		}()
		//      gracefulStop end
		app.Start()

/*	cs := &klarService.KlarServiceImpl{}

	cs.Process(&common.ScanEvent{
		Image:        "686244538589.dkr.ecr.us-east-2.amazonaws.com/devtron:88775627-56-731",
		ImageDigest:  "sha256:49ad28c8b3b7b2485c4baf4d8538fd31cac4d9bd0aa25d120a8cede6d675ad7e",
		AppId:        0,
		EnvId:        0,
		PipelineId:   0,
		CiArtifactId: 0,
		UserId:       0,
	})*/

}
