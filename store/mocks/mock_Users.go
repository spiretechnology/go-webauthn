// Code generated by mockery v2.32.4. DO NOT EDIT.

package mocks

import (
	context "context"

	store "github.com/spiretechnology/go-webauthn/store"
	mock "github.com/stretchr/testify/mock"
)

// MockUsers is an autogenerated mock type for the Users type
type MockUsers struct {
	mock.Mock
}

type MockUsers_Expecter struct {
	mock *mock.Mock
}

func (_m *MockUsers) EXPECT() *MockUsers_Expecter {
	return &MockUsers_Expecter{mock: &_m.Mock}
}

// GetUser provides a mock function with given fields: ctx, id
func (_m *MockUsers) GetUser(ctx context.Context, id string) (*store.User, error) {
	ret := _m.Called(ctx, id)

	var r0 *store.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*store.User, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *store.User); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*store.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUsers_GetUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUser'
type MockUsers_GetUser_Call struct {
	*mock.Call
}

// GetUser is a helper method to define mock.On call
//   - ctx context.Context
//   - id string
func (_e *MockUsers_Expecter) GetUser(ctx interface{}, id interface{}) *MockUsers_GetUser_Call {
	return &MockUsers_GetUser_Call{Call: _e.mock.On("GetUser", ctx, id)}
}

func (_c *MockUsers_GetUser_Call) Run(run func(ctx context.Context, id string)) *MockUsers_GetUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockUsers_GetUser_Call) Return(_a0 *store.User, _a1 error) *MockUsers_GetUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUsers_GetUser_Call) RunAndReturn(run func(context.Context, string) (*store.User, error)) *MockUsers_GetUser_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockUsers creates a new instance of MockUsers. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockUsers(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockUsers {
	mock := &MockUsers{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}