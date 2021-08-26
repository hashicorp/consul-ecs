package mocks

import (
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	mapset "github.com/deckarep/golang-set"
)

type ECSClient struct {
	ecsiface.ECSAPI
	Tasks           []*ecs.Task
	PaginateResults bool
}

func (m *ECSClient) ListTasks(input *ecs.ListTasksInput) (*ecs.ListTasksOutput, error) {
	var taskARNs []*string
	var nextToken *string
	if m.PaginateResults && input.NextToken == nil {
		for _, t := range m.Tasks[:len(m.Tasks)/2] {
			taskARNs = append(taskARNs, t.TaskArn)
		}
		nextToken = m.Tasks[len(m.Tasks)/2].TaskArn
	} else if m.PaginateResults && input.NextToken != nil {
		for _, t := range m.Tasks[len(m.Tasks)/2:] {
			taskARNs = append(taskARNs, t.TaskArn)
		}
	} else {
		for _, t := range m.Tasks {
			taskARNs = append(taskARNs, t.TaskArn)
		}
	}
	return &ecs.ListTasksOutput{
		NextToken: nextToken,
		TaskArns:  taskARNs,
	}, nil
}

func (m *ECSClient) DescribeTasks(input *ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
	var tasksResult []*ecs.Task
	taskARNsInput := mapset.NewSet()
	for _, arn := range input.Tasks {
		taskARNsInput.Add(*arn)
	}

	// Only return Tasks asked for in the input.
	for _, task := range m.Tasks {
		if taskARNsInput.Contains(*task.TaskArn) {
			tasksResult = append(tasksResult, task)
		}
	}
	return &ecs.DescribeTasksOutput{Tasks: tasksResult}, nil
}
