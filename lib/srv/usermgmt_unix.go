//go:build !windows
// +build !windows

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
	"os/exec"
	"os/user"
	"strings"

	"github.com/gravitational/trace"
)

/*
#include <sys/types.h>
#include <pwd.h>
*/
import "C"

// man GROUPADD(8), exit codes section
const groupExistExit = 9

// man USERADD(8), exit codes section
const userExistExit = 9
const userLoggedInExit = 8

type unixMgmt struct{}

var _ UserManagement = &unixMgmt{}

// Lookup implements host user information lookup
func (*unixMgmt) Lookup(username string) (*user.User, error) {
	return user.Lookup(username)
}

func (*unixMgmt) UserGIDs(u *user.User) ([]string, error) {
	return u.GroupIds()
}

// LookupGroup host group information lookup
func (*unixMgmt) LookupGroup(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}

func (*unixMgmt) GetAllUsers() ([]string, error) {
	var result *C.struct_passwd
	names := []string{}
	// getpwent(3), posix compatible way to iterate /etc/passwd.
	// Provided as os/user does not provide any iteration helpers
	C.setpwent()
	defer C.endpwent()
	for {
		result = C.getpwent()
		if result == nil {
			break
		}
		name := result.pw_name
		names = append(names, C.GoString(name))
	}
	if len(names) == 0 {
		return nil, trace.NotFound("failed to find any /etc/passwd entries")
	}
	return names, nil
}

func (*unixMgmt) groupAdd(groupname string) (exitCode int, err error) {
	groupaddBin, err := exec.LookPath("groupadd")
	if err != nil {
		return -1, trace.Wrap(err, "cant find groupadd binary")
	}
	cmd := exec.Command(groupaddBin, groupname)
	err = cmd.Run()
	return cmd.ProcessState.ExitCode(), err
}

func (*unixMgmt) userAdd(username string, groups []string) (exitCode int, err error) {
	useraddBin, err := exec.LookPath("useradd")
	if err != nil {
		return -1, trace.Wrap(err, "cant find useradd binary")
	}
	// useradd --create-home (username) (groups)...
	args := []string{"--create-home", username}
	if len(groups) != 0 {
		args = append(args, "--groups", strings.Join(groups, ","))
	}
	cmd := exec.Command(useraddBin, args...)
	err = cmd.Run()
	return cmd.ProcessState.ExitCode(), err
}

func (*unixMgmt) addUserToGroups(username string, groups []string) (exitCode int, err error) {
	usermodBin, err := exec.LookPath("usermod")
	if err != nil {
		return -1, trace.Wrap(err, "cant find usermod binary")
	}
	args := []string{"-aG"}
	args = append(args, groups...)
	args = append(args, username)
	// usermod -aG (append groups) (username)
	cmd := exec.Command(usermodBin, args...)
	err = cmd.Run()
	return cmd.ProcessState.ExitCode(), err
}

func (*unixMgmt) userDel(username string) (exitCode int, err error) {
	userdelBin, err := exec.LookPath("userdel")
	if err != nil {
		return -1, trace.Wrap(err, "cant find userdel binary")
	}
	// userdel --remove (remove home) username
	cmd := exec.Command(userdelBin, "--remove", username)
	err = cmd.Run()
	return cmd.ProcessState.ExitCode(), err
}
