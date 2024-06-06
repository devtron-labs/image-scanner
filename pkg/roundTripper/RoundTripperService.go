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

package roundTripper

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/sql/repository"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"sync"
)

type RoundTripperService interface {
	GetRoundTripper(scanEvent *common.ImageScanEvent) (http.RoundTripper, error)
}
type RoundTripperServiceImpl struct {
	Logger                        *zap.SugaredLogger
	DockerArtifactStoreRepository repository.DockerArtifactStoreRepository
}

func NewRoundTripperServiceImpl(logger *zap.SugaredLogger,
	DockerArtifactStoreRepository repository.DockerArtifactStoreRepository) *RoundTripperServiceImpl {
	return &RoundTripperServiceImpl{
		Logger:                        logger,
		DockerArtifactStoreRepository: DockerArtifactStoreRepository,
	}
}

type RoundTripperConfig struct {
	Username string
	Password string
	ProxyUrl string
}

var (
	rtMu sync.Mutex
)

const (
	userAgent = `clairctl/1`
)

func (impl *RoundTripperServiceImpl) GetRoundTripper(scanEvent *common.ImageScanEvent) (http.RoundTripper, error) {
	authenticator, dockerRegistry, err := impl.GetAuthenticatorByDockerRegistryId(scanEvent.DockerRegistryId)
	if err != nil {
		impl.Logger.Errorw("error, GetAuthenticatorByDockerRegistryId", "err", err, "dockerRegistryId", scanEvent.DockerRegistryId)
		return nil, err
	}
	rtConfig := &RoundTripperConfig{
		Username: dockerRegistry.Username,
		Password: dockerRegistry.Password,
	}
	rt, err := impl.GetRoundTripperTransport(rtConfig)
	if err != nil {
		impl.Logger.Errorw("error in getting roundTripper", "err", err)
		return nil, err
	}
	var referenceOptions []name.Option
	return impl.UpdateTransportWithReference(rt, scanEvent.Image, authenticator, referenceOptions)
}

func (impl *RoundTripperServiceImpl) GetRoundTripperTransport(config *RoundTripperConfig) (http.RoundTripper, error) {
	return http.DefaultTransport, nil
}

func (impl *RoundTripperServiceImpl) GetAuthenticatorByDockerRegistryId(dockerRegistryId string) (authn.Authenticator, *repository.DockerArtifactStore, error) {
	dockerRegistry, err := impl.DockerArtifactStoreRepository.FindById(dockerRegistryId)
	if err != nil {
		impl.Logger.Errorw("error in getting docker registry by id", "err", err, "id", dockerRegistryId)
		return nil, nil, err
	}
	//case for gcr and artifact registry
	if dockerRegistry.Username == "_json_key" {
		lenPassword := len(dockerRegistry.Password)
		if lenPassword > 1 {
			dockerRegistry.Password = strings.TrimPrefix(dockerRegistry.Password, "'")
			dockerRegistry.Password = strings.TrimSuffix(dockerRegistry.Password, "'")
		}
	}
	authConfig := authn.AuthConfig{
		Username: dockerRegistry.Username,
		Password: dockerRegistry.Password,
	}
	if dockerRegistry.RegistryType == repository.REGISTRYTYPE_ECR {
		accessKey, secretKey := dockerRegistry.AWSAccessKeyId, dockerRegistry.AWSSecretAccessKey
		var creds *credentials.Credentials
		if len(dockerRegistry.AWSAccessKeyId) == 0 || len(dockerRegistry.AWSSecretAccessKey) == 0 {
			sess, err := session.NewSession(&aws.Config{
				Region: &dockerRegistry.AWSRegion,
			})
			if err != nil {
				impl.Logger.Errorw("error in starting aws new session", "err", err)
				return nil, nil, err
			}
			creds = ec2rolecreds.NewCredentials(sess)
		} else {
			creds = credentials.NewStaticCredentials(accessKey, secretKey, "")
		}
		sess, err := session.NewSession(&aws.Config{
			Region:      &dockerRegistry.AWSRegion,
			Credentials: creds,
		})
		if err != nil {
			impl.Logger.Errorw("error in starting aws new session", "err", err)
			return nil, nil, err
		}

		// Create a ECR client with additional configuration
		svc := ecr.New(sess, aws.NewConfig().WithRegion(dockerRegistry.AWSRegion))
		token, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
		if err != nil {
			impl.Logger.Errorw("error in getting auth token from ecr", "err", err)
			return nil, nil, err
		}
		authConfig.Auth = *token.AuthorizationData[0].AuthorizationToken
	}
	authenticatorFromConfig := authn.FromConfig(authConfig)
	return authenticatorFromConfig, dockerRegistry, nil
}
func (impl *RoundTripperServiceImpl) UpdateTransportWithReference(rt http.RoundTripper, ref string, authenticator authn.Authenticator, referenceOptions []name.Option) (http.RoundTripper, error) {
	r, err := name.ParseReference(ref, referenceOptions...)
	if err != nil {
		impl.Logger.Errorw("error in parsing reference", "err", err, "ref", ref)
		return nil, err
	}
	repo := r.Context()
	rtMu.Lock()
	defer rtMu.Unlock()
	rt = transport.NewUserAgent(rt, userAgent)
	rt = transport.NewRetry(rt)
	rt, err = transport.NewWithContext(context.Background(), repo.Registry, authenticator, rt, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		impl.Logger.Errorw("error in getting roundTripper", "err", err)
		return nil, err
	}
	return rt, nil
}
