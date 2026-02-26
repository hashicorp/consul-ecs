// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package mocks

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	mapset "github.com/deckarep/golang-set/v2"
)

// ECSAPI defines the interface for ECS v2 used by the controller.
type ECSAPI interface {
	ListTasks(ctx context.Context, params *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

// ECSClient implements the ECSAPI for testing.
type ECSClient struct {
	Tasks           []types.Task
	PaginateResults bool
}

func (m *ECSClient) ListTasks(ctx context.Context, params *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	var taskARNs []string
	var nextToken *string

	startIndex := 0
	// Simulate NextToken as an index string
	if params.NextToken != nil && *params.NextToken != "" {
		idx, err := strconv.Atoi(*params.NextToken)
		if err != nil {
			return nil, err
		}
		startIndex = idx
	}

	limit := len(m.Tasks)
	if m.PaginateResults {
		pageSize := 2
		if params.MaxResults != nil {
			pageSize = int(*params.MaxResults)
		}

		endIndex := startIndex + pageSize
		if endIndex < len(m.Tasks) {
			limit = endIndex
			nextToken = aws.String(strconv.Itoa(endIndex))
		}
	}

	for i := startIndex; i < limit && i < len(m.Tasks); i++ {
		taskARNs = append(taskARNs, aws.ToString(m.Tasks[i].TaskArn))
	}

	return &ecs.ListTasksOutput{
		NextToken: nextToken,
		TaskArns:  taskARNs,
	}, nil
}

func (m *ECSClient) DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	var tasksResult []types.Task
	taskARNsInput := mapset.NewSet[string]()

	for _, arn := range params.Tasks {
		taskARNsInput.Add(arn)
	}

	for _, task := range m.Tasks {
		if task.TaskArn != nil && taskARNsInput.Contains(*task.TaskArn) {
			tasksResult = append(tasksResult, task)
		}
	}

	return &ecs.DescribeTasksOutput{
		Tasks: tasksResult,
	}, nil
}
