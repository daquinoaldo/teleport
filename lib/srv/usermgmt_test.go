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
	"fmt"
	"os/user"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

type testUserMgmt struct {
	users  map[string][]string
	groups map[string]string
}

func newTestUserMgmt() *testUserMgmt {
	return &testUserMgmt{
		users:  map[string][]string{},
		groups: map[string]string{},
	}
}

func (tm *testUserMgmt) GetAllUsers() ([]string, error) {
	keys := make([]string, 0, len(tm.users))
	for key := range tm.users {
		keys = append(keys, key)
	}
	return keys, nil
}

func (tm *testUserMgmt) Lookup(username string) (*user.User, error) {
	if _, ok := tm.users[username]; !ok {
		return nil, nil
	}
	return &user.User{
		Username: username,
	}, nil
}

func (tm *testUserMgmt) LookupGroup(groupname string) (*user.Group, error) {
	return &user.Group{
		Gid:  tm.groups[groupname],
		Name: groupname,
	}, nil
}

func (tm *testUserMgmt) UserGIDs(u *user.User) ([]string, error) {
	ids := make([]string, 0, len(tm.users[u.Username]))
	for _, id := range tm.users[u.Username] {
		ids = append(ids, tm.groups[id])
	}
	return ids, nil
}

func (tm *testUserMgmt) groupAdd(group string) (int, error) {
	_, ok := tm.groups[group]
	if ok {
		return groupExistExit, trace.AlreadyExists("Group %q, already exists", group)
	}
	tm.groups[group] = fmt.Sprint(len(tm.groups) + 1)
	return 0, nil
}

func (tm *testUserMgmt) userAdd(user string, groups []string) (int, error) {
	_, ok := tm.users[user]
	if ok {
		return userExistExit, trace.AlreadyExists("Group %q, already exists", user)
	}
	tm.users[user] = groups
	return 0, nil
}

func (tm *testUserMgmt) userDel(user string) (int, error) {
	delete(tm.users, user)
	return 0, nil
}

var _ UserManagement = &testUserMgmt{}

func TestUserMgmt_CreateTemporaryUser(t *testing.T) {
	mgmt := newTestUserMgmt()

	// create a user with some groups
	closer, err := createTemporaryUser(mgmt, "bob", []string{"hello", "sudo"})
	require.NoError(t, err)
	require.NotNil(t, closer, "user closer was nil")

	// temproary users must always include the teleport-service group
	require.Equal(t, []string{
		"hello", "sudo", types.TeleportServiceGroup,
	}, mgmt.users["bob"])

	// try creat the same user again
	secondCloser, err := createTemporaryUser(mgmt, "bob", []string{"hello", "sudo"})
	require.True(t, trace.IsAlreadyExists(err))
	require.NotNil(t, secondCloser)

	// Close will remove the user if the user is in the teleport-system group
	require.NoError(t, closer.Close())
	require.NotContains(t, mgmt.users, "bob")

	mgmt.groupAdd("testgroup")
	mgmt.userAdd("simon", []string{})

	// try to create a temporary user for simon
	closer, err = createTemporaryUser(mgmt, "simon", []string{"hello", "sudo"})
	require.True(t, trace.IsAlreadyExists(err))
	require.NotNil(t, closer)

	// close should not delete simon as they already existed outside
	// of the teleport-system group
	require.NoError(t, closer.Close())
	require.Contains(t, mgmt.users, "simon")
}

func TestUserMgmt_DeleteAllTeleportSystemUsers(t *testing.T) {
	type userAndGroups struct {
		user   string
		groups []string
	}

	users := []userAndGroups{
		{"fgh", []string{"teleport-system"}},
		{"xyz", []string{"teleport-system"}},
		{"pqr", []string{"not-deleted"}},
		{"abc", []string{"not-deleted"}},
	}

	remainingUsers := []string{"pqr", "abc"}

	mgmt := newTestUserMgmt()
	for _, user := range users {
		for _, group := range user.groups {
			mgmt.groupAdd(group)
		}
		mgmt.userAdd(user.user, user.groups)
	}

	require.NoError(t, DeleteAllTeleportSystemUsers(mgmt))
	resultingUsers, err := mgmt.GetAllUsers()
	require.NoError(t, err)

	require.ElementsMatch(t, remainingUsers, resultingUsers)
}
