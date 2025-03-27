// Code generated by MockGen. DO NOT EDIT.
// Source: repository/repository.go

// Package mock_repository is a generated GoMock package.
package mock_repository

import (
	entity "auth-echo/model/entity"
	context "context"
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	uuid "github.com/google/uuid"
)

// MockUserRepository is a mock of UserRepository interface.
type MockUserRepository struct {
	ctrl     *gomock.Controller
	recorder *MockUserRepositoryMockRecorder
}

// MockUserRepositoryMockRecorder is the mock recorder for MockUserRepository.
type MockUserRepositoryMockRecorder struct {
	mock *MockUserRepository
}

// NewMockUserRepository creates a new mock instance.
func NewMockUserRepository(ctrl *gomock.Controller) *MockUserRepository {
	mock := &MockUserRepository{ctrl: ctrl}
	mock.recorder = &MockUserRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserRepository) EXPECT() *MockUserRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockUserRepositoryMockRecorder) Create(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockUserRepository)(nil).Create), ctx, user)
}

// GetByID mocks base method.
func (m *MockUserRepository) GetByID(ctx context.Context, userid int) (entity.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", ctx, userid)
	ret0, _ := ret[0].(entity.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockUserRepositoryMockRecorder) GetByID(ctx, userid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockUserRepository)(nil).GetByID), ctx, userid)
}

// GetByUsername mocks base method.
func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (entity.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByUsername", ctx, username)
	ret0, _ := ret[0].(entity.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByUsername indicates an expected call of GetByUsername.
func (mr *MockUserRepositoryMockRecorder) GetByUsername(ctx, username interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByUsername", reflect.TypeOf((*MockUserRepository)(nil).GetByUsername), ctx, username)
}

// MockSessionRepository is a mock of SessionRepository interface.
type MockSessionRepository struct {
	ctrl     *gomock.Controller
	recorder *MockSessionRepositoryMockRecorder
}

// MockSessionRepositoryMockRecorder is the mock recorder for MockSessionRepository.
type MockSessionRepositoryMockRecorder struct {
	mock *MockSessionRepository
}

// NewMockSessionRepository creates a new mock instance.
func NewMockSessionRepository(ctrl *gomock.Controller) *MockSessionRepository {
	mock := &MockSessionRepository{ctrl: ctrl}
	mock.recorder = &MockSessionRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSessionRepository) EXPECT() *MockSessionRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockSessionRepository) Create(ctx context.Context, sessions *entity.Session) (*entity.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, sessions)
	ret0, _ := ret[0].(*entity.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockSessionRepositoryMockRecorder) Create(ctx, sessions interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockSessionRepository)(nil).Create), ctx, sessions)
}

// GetBySessionId mocks base method.
func (m *MockSessionRepository) GetBySessionId(ctx context.Context, sessionId string) (*entity.SessionWithUser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBySessionId", ctx, sessionId)
	ret0, _ := ret[0].(*entity.SessionWithUser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBySessionId indicates an expected call of GetBySessionId.
func (mr *MockSessionRepositoryMockRecorder) GetBySessionId(ctx, sessionId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBySessionId", reflect.TypeOf((*MockSessionRepository)(nil).GetBySessionId), ctx, sessionId)
}

// GetByToken mocks base method.
func (m *MockSessionRepository) GetByToken(ctx context.Context, refreshToken string) (*entity.SessionWithUser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByToken", ctx, refreshToken)
	ret0, _ := ret[0].(*entity.SessionWithUser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByToken indicates an expected call of GetByToken.
func (mr *MockSessionRepositoryMockRecorder) GetByToken(ctx, refreshToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByToken", reflect.TypeOf((*MockSessionRepository)(nil).GetByToken), ctx, refreshToken)
}

// InvalidateByTokenFamily mocks base method.
func (m *MockSessionRepository) InvalidateByTokenFamily(ctx context.Context, tokenFamily uuid.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InvalidateByTokenFamily", ctx, tokenFamily)
	ret0, _ := ret[0].(error)
	return ret0
}

// InvalidateByTokenFamily indicates an expected call of InvalidateByTokenFamily.
func (mr *MockSessionRepositoryMockRecorder) InvalidateByTokenFamily(ctx, tokenFamily interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InvalidateByTokenFamily", reflect.TypeOf((*MockSessionRepository)(nil).InvalidateByTokenFamily), ctx, tokenFamily)
}

// RotateToken mocks base method.
func (m *MockSessionRepository) RotateToken(ctx context.Context, session *entity.Session) (*entity.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RotateToken", ctx, session)
	ret0, _ := ret[0].(*entity.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RotateToken indicates an expected call of RotateToken.
func (mr *MockSessionRepositoryMockRecorder) RotateToken(ctx, session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RotateToken", reflect.TypeOf((*MockSessionRepository)(nil).RotateToken), ctx, session)
}

// MockLoginDevicesRepository is a mock of LoginDevicesRepository interface.
type MockLoginDevicesRepository struct {
	ctrl     *gomock.Controller
	recorder *MockLoginDevicesRepositoryMockRecorder
}

// MockLoginDevicesRepositoryMockRecorder is the mock recorder for MockLoginDevicesRepository.
type MockLoginDevicesRepositoryMockRecorder struct {
	mock *MockLoginDevicesRepository
}

// NewMockLoginDevicesRepository creates a new mock instance.
func NewMockLoginDevicesRepository(ctrl *gomock.Controller) *MockLoginDevicesRepository {
	mock := &MockLoginDevicesRepository{ctrl: ctrl}
	mock.recorder = &MockLoginDevicesRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLoginDevicesRepository) EXPECT() *MockLoginDevicesRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockLoginDevicesRepository) Create(ctx context.Context, loginDevice *entity.UserLoginDevice) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, loginDevice)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockLoginDevicesRepositoryMockRecorder) Create(ctx, loginDevice interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockLoginDevicesRepository)(nil).Create), ctx, loginDevice)
}

// GetByDeviceId mocks base method.
func (m *MockLoginDevicesRepository) GetByDeviceId(ctx context.Context, deviceIdentity string) (*entity.UserLoginDevice, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByDeviceId", ctx, deviceIdentity)
	ret0, _ := ret[0].(*entity.UserLoginDevice)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByDeviceId indicates an expected call of GetByDeviceId.
func (mr *MockLoginDevicesRepositoryMockRecorder) GetByDeviceId(ctx, deviceIdentity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByDeviceId", reflect.TypeOf((*MockLoginDevicesRepository)(nil).GetByDeviceId), ctx, deviceIdentity)
}

// UpdateLastLogin mocks base method.
func (m *MockLoginDevicesRepository) UpdateLastLogin(ctx context.Context, deviceId, userAgent string, ipAddr net.IP) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateLastLogin", ctx, deviceId, userAgent, ipAddr)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateLastLogin indicates an expected call of UpdateLastLogin.
func (mr *MockLoginDevicesRepositoryMockRecorder) UpdateLastLogin(ctx, deviceId, userAgent, ipAddr interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateLastLogin", reflect.TypeOf((*MockLoginDevicesRepository)(nil).UpdateLastLogin), ctx, deviceId, userAgent, ipAddr)
}
