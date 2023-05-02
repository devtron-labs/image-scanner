package cli_util

import (
	"context"
	common_util "github.com/devtron-labs/image-scanner/internal/step-lib/util/common-util"
	"io"
	"log"
	"os/exec"
	"sync"
)

type CliOutputType string

const (
	CliOutPutTypeStatic CliOutputType = "STATIC"
	CliOutPutTypeStream CliOutputType = "STREAM"
)

func HandleCliRequest(baseCommand, outputFileName string, ctx context.Context, outputType CliOutputType, args map[string]string) (output []byte, err error) {
	//converting maps of args and their values to a slice of string for execution
	argsSlice := make([]string, 0, len(args))
	for arg, value := range args {
		//assuming '-' or '--' is provided by user (if applicable)
		argsSlice = append(argsSlice, arg)
		argsSlice = append(argsSlice, value)
	}
	command := exec.CommandContext(ctx, baseCommand, argsSlice...)
	if outputType == CliOutPutTypeStream { //TODO: make async in further feature iterations
		err = executeStreamCliRequest(command, outputFileName)
	} else if outputType == CliOutPutTypeStatic {
		err, output = executeStaticCliRequest(command, outputFileName)
	}
	if err != nil {
		log.Println("error in executing cli request", "err", err, "req", command)
		return output, err
	}
	return output, nil
}

func executeStaticCliRequest(command *exec.Cmd, outputFileName string) (error, []byte) {
	op, err := command.CombinedOutput()
	if err != nil {
		log.Println("error in running command", "err", err)
		return err, nil
	}
	if outputFileName != "" && op != nil {
		err = common_util.WriteFile(outputFileName, op)
		if err != nil {
			log.Println("error in writing cli static command output to file", "err", err)
			return err, nil
		}
	}
	return nil, op
}

func executeStreamCliRequest(command *exec.Cmd, outputFileName string) error {
	var stdout []byte
	var errOutputWrite error
	stdoutIn, _ := command.StdoutPipe()
	err := command.Start()
	if err != nil {
		log.Println("failed to start command execution", "err", err)
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		errOutputWrite = copyAndWriteToOutputFile(stdoutIn, outputFileName)
		wg.Done()
	}()

	wg.Wait()
	err = command.Wait()
	if err != nil {
		log.Println("got error in waiting for command", "err", err)
		return err
	}
	if errOutputWrite != nil {
		log.Println("failed to copy and write stream output to file", "err", errOutputWrite)
		return errOutputWrite
	}
	outStr := string(stdout)
	log.Printf("out:%s\n", outStr)
	return nil
}

func copyAndWriteToOutputFile(r io.Reader, outputFileName string) error {
	var out []byte
	buf := make([]byte, 1024, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			d := buf[:n]
			out = append(out, d...)
			if outputFileName != "" && out != nil {
				errWrite := common_util.WriteFile(outputFileName, out)
				if errWrite != nil {
					log.Println("error in writing buffer output to file", "err", err)
					return errWrite
				}
			}
		}
		if err != nil && err != io.EOF {
			log.Println("error in reading from buffer", "err", err)
			return err
		} else {
			return nil
		}
	}
}
