// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package mocks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	mapset "github.com/deckarep/golang-set/v2"
)

type ECSClient struct {
	Tasks           []types.Task
	PaginateResults bool
}

type ECSAPI interface {
	ListTasks(ctx context.Context, input *ecs.ListTasksInput, opts ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, opts ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

func (m *ECSClient) ListTasks(ctx context.Context, input *ecs.ListTasksInput, opts ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	var taskARNs []string
	var nextToken *string

	if m.PaginateResults && input.NextToken == nil {
		half := len(m.Tasks) / 2
		for _, t := range m.Tasks[:half] {
			taskARNs = append(taskARNs, aws.ToString(t.TaskArn))
		}
		if half < len(m.Tasks) {
			nextToken = m.Tasks[half].TaskArn
		}
	} else if m.PaginateResults && input.NextToken != nil {
		half := len(m.Tasks) / 2
		for _, t := range m.Tasks[half:] {
			taskARNs = append(taskARNs, aws.ToString(t.TaskArn))
		}
	} else {
		for _, t := range m.Tasks {
			taskARNs = append(taskARNs, aws.ToString(t.TaskArn))
		}
	}

	return &ecs.ListTasksOutput{
		NextToken: nextToken,
		TaskArns:  taskARNs,
	}, nil
}

func (m *ECSClient) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, opts ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	var tasksResult []types.Task
	taskARNsInput := mapset.NewSet[string]()

	for _, arn := range input.Tasks {
		taskARNsInput.Add(arn)
	}

	for _, task := range m.Tasks {
		if task.TaskArn != nil && taskARNsInput.Contains(*task.TaskArn) {
			tasksResult = append(tasksResult, task)
		}
	}

	return &ecs.DescribeTasksOutput{Tasks: tasksResult}, nil
}
