/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cli_util

import (
	"context"
	"github.com/devtron-labs/image-scanner/common"
	common_util "github.com/devtron-labs/image-scanner/internals/step-lib/util/common-util"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

type CliOutputType string

const (
	CliOutPutTypeStatic CliOutputType = "STATIC"
	CliOutPutTypeStream CliOutputType = "STREAM"
)

func HandleCliRequest(baseCommand, outputFileName string, ctx context.Context, outputType CliOutputType, args map[string]string, cliCommandEnv []string) (output []byte, err error) {
	//converting maps of args and their values to a slice of string for execution
	argsSlice := make([]string, 0, len(args))
	for arg, value := range args {
		//assuming '-' or '--' is provided by user (if applicable)
		argsSlice = append(argsSlice, arg)
		if value != "" {
			argsSlice = append(argsSlice, value)
		}
	}
	command := exec.CommandContext(ctx, common.SHELL_COMMAND, common.COMMAND_ARGS, baseCommand)
	command.Env = append(command.Env, cliCommandEnv...)
	if outputType == CliOutPutTypeStream { //TODO: make async in further feature iterations
		err = executeStreamCliRequest(command, outputFileName)
	} else if outputType == CliOutPutTypeStatic {
		err, output = executeStaticCliRequest(command, outputFileName)
	}
	if err != nil {
		log.Println("error in executing cli request", "err", err, "req", command, string(output))
		return output, err
	}
	return output, nil
}

func executeStaticCliRequest(command *exec.Cmd, outputFileName string) (error, []byte) {
	op, err := command.CombinedOutput()
	if err != nil {
		log.Println("error in running command", "err", err, "op", string(op))
		return err, op
	}
	// If output is already stored in file, considering the output from file (file is created by tool over here)
	if outputFileName != "" && op != nil {
		if _, err := os.Stat(outputFileName); err == nil {
			op, err = os.ReadFile(outputFileName)
			if err != nil {
				log.Println("error in reading output file", "err", err)
				return err, nil
			}
		} else {
			err = common_util.WriteFile(outputFileName, op)
			if err != nil {
				log.Println("error in writing cli static command output to file", "err", err)
				return err, nil
			}
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
