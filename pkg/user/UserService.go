package user

import (
	"github.com/devtron-labs/image-scanner/internals/sql/bean"
	"github.com/devtron-labs/image-scanner/internals/sql/repository"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type UserService interface {
	GetAll() ([]bean.UserInfo, error)
	GetUserByEmail(emailId string) (*bean.UserInfo, error)
	GetByIds(ids []int32) ([]bean.UserInfo, error)
}

type UserServiceImpl struct {
	logger         *zap.SugaredLogger
	userRepository repository.UserRepository
}

func NewUserServiceImpl(logger *zap.SugaredLogger, userRepository repository.UserRepository) *UserServiceImpl {
	serviceImpl := &UserServiceImpl{

		logger:         logger,
		userRepository: userRepository,
	}
	return serviceImpl
}

func containsArr(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (impl UserServiceImpl) GetAll() ([]bean.UserInfo, error) {
	model, err := impl.userRepository.GetAll()
	if err != nil {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	var response []bean.UserInfo
	for _, m := range model {
		response = append(response, bean.UserInfo{
			Id:      m.Id,
			EmailId: m.EmailId,
			Groups:  make([]string, 0),
		})
	}
	if response == nil || len(response) == 0 {
		response = make([]bean.UserInfo, 0)
	}
	return response, nil
}

func (impl UserServiceImpl) GetUserByEmail(emailId string) (*bean.UserInfo, error) {
	model, err := impl.userRepository.FetchUserByEmail(emailId)
	if err != nil {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	response := &bean.UserInfo{
		Id:          model.Id,
		EmailId:     model.EmailId,
		AccessToken: model.AccessToken,
	}

	return response, nil
}

func (impl UserServiceImpl) GetByIds(ids []int32) ([]bean.UserInfo, error) {
	var beans []bean.UserInfo
	models, err := impl.userRepository.GetByIds(ids)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	if len(models) > 0 {
		for _, item := range models {
			beans = append(beans, bean.UserInfo{Id: item.Id, EmailId: item.EmailId})
		}
	}
	return beans, nil
}
