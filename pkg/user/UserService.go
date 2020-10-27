package user

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type UserService interface {
	GetAll() ([]common.UserInfo, error)
	GetUserByEmail(emailId string) (*common.UserInfo, error)
	GetByIds(ids []int32) ([]common.UserInfo, error)
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

func (impl UserServiceImpl) GetAll() ([]common.UserInfo, error) {
	model, err := impl.userRepository.GetAll()
	if err != nil {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	var response []common.UserInfo
	for _, m := range model {
		response = append(response, common.UserInfo{
			Id:          m.Id,
			EmailId:     m.EmailId,
			Groups:      make([]string, 0),
		})
	}
	if response == nil || len(response) == 0 {
		response = make([]common.UserInfo, 0)
	}
	return response, nil
}

func (impl UserServiceImpl) GetUserByEmail(emailId string) (*common.UserInfo, error) {
	model, err := impl.userRepository.FetchUserByEmail(emailId)
	if err != nil {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	response := &common.UserInfo{
		Id:          model.Id,
		EmailId:     model.EmailId,
		AccessToken: model.AccessToken,
	}

	return response, nil
}

func (impl UserServiceImpl) GetByIds(ids []int32) ([]common.UserInfo, error) {
	var beans []common.UserInfo
	models, err := impl.userRepository.GetByIds(ids)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error while fetching user from db", "error", err)
		return nil, err
	}
	if len(models) > 0 {
		for _, item := range models {
			beans = append(beans, common.UserInfo{Id: item.Id, EmailId: item.EmailId})
		}
	}
	return beans, nil
}
