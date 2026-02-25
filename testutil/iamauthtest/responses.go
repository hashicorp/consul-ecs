// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package iamauthtest

// This file is copied from these Consul files:
// https://github.com/hashicorp/consul/blob/76c03872b709297b7649cb3f8999c3d1323361fb/internal/iamauth/responses/responses.go
// https://github.com/hashicorp/consul/blob/76c03872b709297b7649cb3f8999c3d1323361fb/internal/iamauth/responsestest/testing.go

import (
	"encoding/xml"
	"strings"
)

func MakeGetCallerIdentityResponse(arn, userId, accountId string) GetCallerIdentityResponse {
	// Sanity check the UserId for unit tests.
	parsed := parseArn(arn)
	switch parsed.Type {
	case "assumed-role":
		if !strings.Contains(userId, ":") {
			panic("UserId for assumed-role in GetCallerIdentity response must be '<uniqueId>:<session>'")
		}
	default:
		if strings.Contains(userId, ":") {
			panic("UserId in GetCallerIdentity must not contain ':'")
		}
	}

	return GetCallerIdentityResponse{
		GetCallerIdentityResult: []GetCallerIdentityResult{
			{
				Arn:     arn,
				UserId:  userId,
				Account: accountId,
			},
		},
	}
}

func MakeGetRoleResponse(arn, id string, tags Tags) GetRoleResponse {
	if strings.Contains(id, ":") {
		panic("RoleId in GetRole response must not contain ':'")
	}
	parsed := parseArn(arn)
	return GetRoleResponse{
		GetRoleResult: []GetRoleResult{
			{
				Role: Role{
					Arn:      arn,
					Path:     parsed.Path,
					RoleId:   id,
					RoleName: parsed.FriendlyName,
					Tags:     tags,
				},
			},
		},
	}
}

func MakeGetUserResponse(arn, id string, tags Tags) GetUserResponse {
	if strings.Contains(id, ":") {
		panic("UserId in GetUser resposne must not contain ':'")
	}
	parsed := parseArn(arn)
	return GetUserResponse{
		GetUserResult: []GetUserResult{
			{
				User: User{
					Arn:      arn,
					Path:     parsed.Path,
					UserId:   id,
					UserName: parsed.FriendlyName,
					Tags:     tags,
				},
			},
		},
	}
}

func parseArn(arn string) *ParsedArn {
	parsed, err := ParseArn(arn)
	if err != nil {
		// For testing, just fail immediately.
		panic(err)
	}
	return parsed
}

type GetCallerIdentityResponse struct {
	XMLName                 xml.Name                  `xml:"GetCallerIdentityResponse"`
	GetCallerIdentityResult []GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata        []ResponseMetadata        `xml:"ResponseMetadata"`
}

type GetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

// IAMEntity is an interface for getting details from an IAM Role or User.
type IAMEntity interface {
	EntityPath() string
	EntityArn() string
	EntityName() string
	EntityId() string
	EntityTags() map[string]string
}

var _ IAMEntity = (*Role)(nil)
var _ IAMEntity = (*User)(nil)

type GetRoleResponse struct {
	XMLName          xml.Name           `xml:"GetRoleResponse"`
	GetRoleResult    []GetRoleResult    `xml:"GetRoleResult"`
	ResponseMetadata []ResponseMetadata `xml:"ResponseMetadata"`
}

type GetRoleResult struct {
	Role Role `xml:"Role"`
}

type Role struct {
	Arn      string `xml:"Arn"`
	Path     string `xml:"Path"`
	RoleId   string `xml:"RoleId"`
	RoleName string `xml:"RoleName"`
	Tags     Tags   `xml:"Tags"`
}

func (r *Role) EntityPath() string            { return r.Path }
func (r *Role) EntityArn() string             { return r.Arn }
func (r *Role) EntityName() string            { return r.RoleName }
func (r *Role) EntityId() string              { return r.RoleId }
func (r *Role) EntityTags() map[string]string { return tagsToMap(r.Tags) }

type GetUserResponse struct {
	XMLName          xml.Name           `xml:"GetUserResponse"`
	GetUserResult    []GetUserResult    `xml:"GetUserResult"`
	ResponseMetadata []ResponseMetadata `xml:"ResponseMetadata"`
}

type GetUserResult struct {
	User User `xml:"User"`
}

type User struct {
	Arn      string `xml:"Arn"`
	Path     string `xml:"Path"`
	UserId   string `xml:"UserId"`
	UserName string `xml:"UserName"`
	Tags     Tags   `xml:"Tags"`
}

func (u *User) EntityPath() string            { return u.Path }
func (u *User) EntityArn() string             { return u.Arn }
func (u *User) EntityName() string            { return u.UserName }
func (u *User) EntityId() string              { return u.UserId }
func (u *User) EntityTags() map[string]string { return tagsToMap(u.Tags) }

type Tags struct {
	Members []TagMember `xml:"member"`
}

type TagMember struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

func tagsToMap(tags Tags) map[string]string {
	result := map[string]string{}
	for _, tag := range tags.Members {
		result[tag.Key] = tag.Value
	}
	return result
}
