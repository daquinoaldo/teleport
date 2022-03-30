/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package srv

import (
	"os/user"
	"runtime"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/siddontang/go/log"
)

func NewUserManagement() (UserManagement, error) {
	if runtime.GOOS == "windows" {
		return nil, trace.NotImplemented("Host user creation management is only supported on linux")
	}
	return &unixMgmt{}, nil
}

type UserManagement interface {
	GetAllUsers() ([]string, error)
	UserGIDs(*user.User) ([]string, error)
	Lookup(string) (*user.User, error)
	LookupGroup(string) (*user.Group, error)
	groupAdd(string) (int, error)
	userAdd(string, []string) (int, error)
	userDel(string) (int, error)
}

type userCloser struct {
	mgmt UserManagement
	user string
}

func (u *userCloser) Close() error {
	teleportGroup, err := u.mgmt.LookupGroup(types.TeleportServiceGroup)
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(deleteUserInGroup(u.mgmt, u.user, teleportGroup.Gid))
}

// todo(lxea): add tests now that there is an interface

func createGroupIfNotExist(mgmt UserManagement, group string) error {
	_, err := mgmt.LookupGroup(group)
	if err != nil && err != user.UnknownGroupError(group) {
		return trace.Wrap(err)
	}
	code, err := mgmt.groupAdd(group)
	if code == groupExistExit {
		return nil
	}
	return trace.Wrap(err)
}

func DeleteAllTeleportSystemUsers(mgmt UserManagement) error {
	users, err := mgmt.GetAllUsers()
	if err != nil {
		return err
	}
	teleportGroup, err := mgmt.LookupGroup(types.TeleportServiceGroup)
	if err != nil {
		return trace.Wrap(err)
	}
	var errs []error
	for _, u := range users {
		errs = append(errs, deleteUserInGroup(mgmt, u, teleportGroup.Gid))
	}
	return trace.NewAggregate(errs...)
}

// deleteUserInGroup deletes the specified user only if they are
// present in the group
func deleteUserInGroup(mgmt UserManagement, username string, gid string) error {
	tempUser, err := mgmt.Lookup(username)
	if err != nil {
		return trace.Wrap(err)
	}
	ids, err := mgmt.UserGIDs(tempUser)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, id := range ids {
		if id == gid {
			code, err := mgmt.userDel(username)
			if code == userLoggedInExit {
				log.Warnf("Not deleting user %q, user has another session, or running process", username)
				return nil
			}
			return trace.Wrap(err)
		}
	}
	log.Debugf("User %q not deleted: not a temporary user", username)
	return nil
}

func createTemporaryUser(mgmt UserManagement, username string, groups []string) (closer *userCloser, err error) {
	tempUser, err := mgmt.Lookup(username)
	if err != nil && err != user.UnknownUserError(username) {
		return nil, trace.Wrap(err)
	}
	if tempUser != nil {
		// try to delete even if the user already exists as only users
		// in the teleport-system group will be deleted and this way
		// if a user creates multiple sessions the account will
		// succeed in deletion
		return &userCloser{
			user: username,
			mgmt: mgmt,
		}, trace.AlreadyExists("User already exists")
	}

	var errs []error
	for _, group := range append(groups, types.TeleportServiceGroup) {
		err := createGroupIfNotExist(mgmt, group)
		if err != nil {
			errs = append(errs, err)
			continue
		}
	}
	if err := trace.NewAggregate(errs...); err != nil {
		return nil, trace.WrapWithMessage(err, "error while creating groups")
	}

	code, err := mgmt.userAdd(username, append(groups, types.TeleportServiceGroup))
	if code != userExistExit && err != nil {
		return nil, trace.WrapWithMessage(err, "error while creating user")
	}
	return &userCloser{
		user: username,
		mgmt: mgmt,
	}, nil
}
