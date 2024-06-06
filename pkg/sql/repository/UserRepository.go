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

/*
@author: vikram@github.com/devtron-labs
@description: user crud
*/
package repository

import (
	"fmt"
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"time"
)

type UserRepository interface {
	CreateUser(userModel *UserModel, tx *pg.Tx) (*UserModel, error)
	UpdateUser(userModel *UserModel, tx *pg.Tx) (*UserModel, error)
	GetById(id int32) (*UserModel, error)
	GetAll() ([]UserModel, error)
	GetUsersByFilter(size int, from int) ([]UserModel, error)
	FetchUserByEmail(email string) (bean.UserInfo, error)
	FetchUserByEmailV2(email string) (*UserModel, error)
	FetchUserDetailByEmailV2(email string) (*UserModel, error)
	GetByIds(ids []int32) ([]UserModel, error)
	DeleteUser(userModel *UserModel, tx *pg.Tx) (bool, error)

	GetConnection() (dbConnection *pg.DB)
	GetByEmailId(email string) ([]UserModel, error)
}

type UserRepositoryImpl struct {
	dbConnection *pg.DB
	Logger       *zap.SugaredLogger
}

func NewUserRepositoryImpl(dbConnection *pg.DB) *UserRepositoryImpl {
	return &UserRepositoryImpl{dbConnection: dbConnection}
}

type UserModel struct {
	TableName   struct{} `sql:"users"`
	Id          int32    `sql:"id,pk"`
	EmailId     string   `sql:"email_id,notnull"`
	AccessToken string   `sql:"access_token"`
	Active      bool     `sql:"active,notnull"`
	AuditLog
}
type UserRoleModel struct {
	TableName struct{} `sql:"user_roles"`
	Id        int      `sql:"id,pk"`
	UserId    int32    `sql:"user_id,notnull"`
	RoleId    int      `sql:"role_id,notnull"`
	User      UserModel
	AuditLog
}
type AuditLog struct {
	CreatedOn time.Time `sql:"created_on"`
	CreatedBy int32     `sql:"created_by"`
	UpdatedOn time.Time `sql:"updated_on"`
	UpdatedBy int32     `sql:"updated_by"`
}

func (impl UserRepositoryImpl) CreateUser(userModel *UserModel, tx *pg.Tx) (*UserModel, error) {
	err := tx.Insert(userModel)
	if err != nil {
		fmt.Println("Exception;", err)
		return userModel, err
	}
	//TODO - Create Entry In UserRole With Default Role for User
	return userModel, nil
}
func (impl UserRepositoryImpl) UpdateUser(userModel *UserModel, tx *pg.Tx) (*UserModel, error) {
	err := tx.Update(userModel)
	if err != nil {
		fmt.Println("Exception;", err)
		return userModel, err
	}

	//TODO - Create Entry In UserRole With Default Role for User

	return userModel, nil
}
func (impl UserRepositoryImpl) GetById(id int32) (*UserModel, error) {
	var model UserModel
	err := impl.dbConnection.Model(&model).Where("id = ?", id).Where("active = ?", true).Select()
	return &model, err
}
func (impl UserRepositoryImpl) GetAll() ([]UserModel, error) {
	var userModel []UserModel
	err := impl.dbConnection.Model(&userModel).Where("active = ?", true).Order("updated_on desc").Select()
	return userModel, err
}
func (impl UserRepositoryImpl) GetUsersByFilter(size int, from int) ([]UserModel, error) {
	var userModel []UserModel
	/*err := impl.
	dbConnection.Model(&userModel).
	Column("user_model.id,user_model.email_id,user_model.access_token,").
	Order("user_model.email_id DESC").
	Offset(from).
	Limit(size).
	Select()
	*/
	query := "SELECT u.id, u.email_id, u.access_token FROM users u WHERE u.active = true" +
		" ORDER by u.email_id DESC LIMIT ? OFFSET ?;"
	_, err := impl.dbConnection.Query(&userModel, query, size, from)
	return userModel, err
}

func (impl UserRepositoryImpl) FetchUserByEmail(email string) (bean.UserInfo, error) {
	var users bean.UserInfo

	query := "SELECT u.id, u.email_id, u.access_token FROM users u" +
		" WHERE u.email_id ILIKE ? order by u.updated_on desc"
	_, err := impl.dbConnection.Query(&users, query, email)
	if err != nil {
		impl.Logger.Error("Exception caught:", err)
		return users, err
	}

	return users, nil
}

func (impl UserRepositoryImpl) FetchUserByEmailV2(email string) (*UserModel, error) {
	var model UserModel
	err := impl.
		dbConnection.Model(&model).
		Column("user_model.id,user_model.email_id,user_model.access_token,").
		Where("email_id = ?", email).
		Select()
	return &model, err
}
func (impl UserRepositoryImpl) FetchUserDetailByEmailV2(email string) (*UserModel, error) {
	var model UserModel
	err := impl.dbConnection.
		Model(&model).
		Column("user_model.*", "role_model").
		Join("INNER JOIN user_roles ur ON ur.user_id=user_model.id").
		Join("INNER JOIN roles r ON r.id=ur.role_id").
		Where("WHERE user_model.email_id= ?", email).
		Where("user_model.active = ?", true).
		Limit(1).
		Select()
	return &model, err
}
func (impl UserRepositoryImpl) GetByIds(ids []int32) ([]UserModel, error) {
	var model []UserModel
	err := impl.dbConnection.Model(&model).Where("id in (?)", pg.In(ids)).Select()
	return model, err
}

func (impl UserRepositoryImpl) DeleteUser(userModel *UserModel, tx *pg.Tx) (bool, error) {
	err := tx.Delete(userModel)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (impl *UserRepositoryImpl) GetConnection() (dbConnection *pg.DB) {
	return impl.dbConnection
}

func (impl UserRepositoryImpl) GetByEmailId(email string) ([]UserModel, error) {
	var model []UserModel
	err := impl.dbConnection.Model(&model).Where("email_id like (?)", "%"+email+"%").Select()
	return model, err
}
