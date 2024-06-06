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

package repository

import (
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"github.com/go-pg/pg"
)

type CvePolicy struct {
	tableName     struct{} `sql:"cve_policy_control" pg:",discard_unknown_columns"`
	Id            int      `sql:"id,pk"`
	Global        bool
	ClusterId     int
	EnvironmentId int
	AppId         int
	CVEStoreId    int
	Action        PolicyAction
	Severity      bean.Severity
	Deleted       bool
	AuditLog
	*CveStore
}

type PolicyAction int

const (
	Inherit PolicyAction = iota
	Allow
	Block
)

func (d PolicyAction) String() string {
	return [...]string{"Inherit", "Allow", "Block"}[d]
}

type PolicyLevel int

const (
	Global PolicyLevel = iota
	Cluster
	Environment
	App
)

func (d PolicyLevel) String() string {
	return [...]string{"Global", "Cluster", "Environment", "App"}[d]
}

func (policy *CvePolicy) PolicyLevel() PolicyLevel {
	if policy.ClusterId != 0 {
		return Cluster
	} else if policy.EnvironmentId != 0 {
		return Environment
	} else if policy.AppId != 0 {
		return App
	} else {
		return Global
	}
}

//------------------

type CvePolicyRepository interface {
	GetEnvPolicies(clusterId int, environmentId int) (policies []*CvePolicy, err error)
	GetAppEnvPolicies(clusterId int, environmentId int, appId int) (policies []*CvePolicy, err error)
}
type CvePolicyRepositoryImpl struct {
	dbConnection *pg.DB
}

func (impl *CvePolicyRepositoryImpl) GetEnvPolicies(clusterId int, environmentId int) (policies []*CvePolicy, err error) {
	err = impl.dbConnection.Model(policies).
		Where("global = true").
		Where("cluster_id= ?", clusterId).
		Where("environmentId = ?", environmentId).
		Where("deleted = false").
		Select()
	return policies, err
}

func (impl *CvePolicyRepositoryImpl) GetAppEnvPolicies(clusterId int, environmentId int, appId int) (policies []*CvePolicy, err error) {
	err = impl.dbConnection.Model(policies).
		Where("global = true").
		Where("cluster_id= ?", clusterId).
		Where("environment_id = ?", environmentId).
		Where("app_id = ?", appId).
		Where("deleted = false").
		Select()
	return policies, err
}
