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

package pubsub

import (
	"encoding/json"
	pubsub "github.com/devtron-labs/common-lib/pubsub-lib"
	"go.uber.org/zap"
)

type TestPublish interface {
	PublishForScan(channel string, payload interface{}) error
}

type TestPublishImpl struct {
	pubSubClient *pubsub.PubSubClientServiceImpl
	logger       *zap.SugaredLogger
}

func NewTestPublishImpl(pubSubClient *pubsub.PubSubClientServiceImpl,
	logger *zap.SugaredLogger) *TestPublishImpl {
	ns := &TestPublishImpl{
		pubSubClient: pubSubClient,
		logger:       logger,
	}
	return ns
}

func (impl *TestPublishImpl) PublishForScan(channel string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	err = impl.pubSubClient.Publish(channel, string(body))
	if err != nil {
		impl.logger.Errorw("Error while publishing request", "topic", channel, "error", err)
	}
	return err
}
