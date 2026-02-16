package usecase

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/mocks"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestRegister_Success(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	input := RegisterInput{
		Email:    "test@example.com",
		Username: "testuser1",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "testuser").Return(nil, nil)
	mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).
		Run(func(args mock.Arguments) {
			user := args.Get(1).(*entity.User)
			user.ID = 1
			user.CreatedAt = time.Now()
		}).
		Return(nil)

	output, err := uc.Register(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, int64(1), output.ID)
	assert.Equal(t, "test@example.com", output.Email)
	assert.Equal(t, "testuser", output.Username)
	assert.False(t, output.CreatedAt.IsZero())
	mockRepo.AssertExpectations(t)
}

func TestRegister_PasswordIsHashed(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	input := RegisterInput{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "testuser").Return(nil, nil)
	mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).
		Run(func(args mock.Arguments) {
			user := args.Get(1).(*entity.User)
			// Verify the password stored is a bcrypt hash, not plaintext
			assert.NotEqual(t, "password123", user.Password)
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("password123"))
			assert.NoError(t, err)
		}).
		Return(nil)

	_, err := uc.Register(context.Background(), input)
	require.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestRegister_TrimsWhitespace(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	input := RegisterInput{
		Email:    "  test@example.com  ",
		Username: "  testuser  ",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "testuser").Return(nil, nil)
	mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).
		Run(func(args mock.Arguments) {
			user := args.Get(1).(*entity.User)
			assert.Equal(t, "test@example.com", user.Email)
			assert.Equal(t, "testuser", user.Username)
		}).
		Return(nil)

	output, err := uc.Register(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "test@example.com", output.Email)
	assert.Equal(t, "testuser", output.Username)
	mockRepo.AssertExpectations(t)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	existingUser := &entity.User{ID: 1, Email: "existing@example.com"}
	mockRepo.On("GetByEmail", mock.Anything, "existing@example.com").Return(existingUser, nil)

	input := RegisterInput{
		Email:    "existing@example.com",
		Username: "testuser",
		Password: "password123",
	}

	output, err := uc.Register(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusBadRequest, appErr.Code)
	assert.Equal(t, "email already exists", appErr.Message)
	mockRepo.AssertExpectations(t)
	mockRepo.AssertNotCalled(t, "GetByUsername")
	mockRepo.AssertNotCalled(t, "Create")
}

func TestRegister_UsernameAlreadyExists(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	existingUser := &entity.User{ID: 2, Username: "taken"}
	mockRepo.On("GetByEmail", mock.Anything, "new@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "taken").Return(existingUser, nil)

	input := RegisterInput{
		Email:    "new@example.com",
		Username: "taken",
		Password: "password123",
	}

	output, err := uc.Register(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusBadRequest, appErr.Code)
	assert.Equal(t, "username already exists", appErr.Message)
	mockRepo.AssertExpectations(t)
	mockRepo.AssertNotCalled(t, "Create")
}

func TestRegister_GetByEmailError(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	dbErr := apperror.New(http.StatusInternalServerError, "db error")
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, dbErr)

	input := RegisterInput{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}

	output, err := uc.Register(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

func TestRegister_GetByUsernameError(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	dbErr := apperror.New(http.StatusInternalServerError, "db error")
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "testuser").Return(nil, dbErr)

	input := RegisterInput{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}

	output, err := uc.Register(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

func TestRegister_CreateError(t *testing.T) {
	t.Parallel()

	mockRepo := new(mocks.MockUserRepository)
	uc := NewUserUsecase(mockRepo)

	dbErr := apperror.New(http.StatusInternalServerError, "failed to create user")
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, nil)
	mockRepo.On("GetByUsername", mock.Anything, "testuser").Return(nil, nil)
	mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(dbErr)

	input := RegisterInput{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}

	output, err := uc.Register(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}
