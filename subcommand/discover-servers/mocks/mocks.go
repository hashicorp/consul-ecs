package mocks

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
)

func MockConsulServerTask(expectedIP, taskARN string) *ecs.Task {
	serverContainer := &ecs.Container{
		ContainerArn: aws.String("arn:aws:ecs:us-east-1:123456789:container/test/abcdef/uvwxyz"),
		HealthStatus: aws.String("UNKNOWN"),
		LastStatus:   aws.String("RUNNING"),
		Image:        aws.String("docker.mirror.hashicorp.services/hashicorp/consul:1.9.5"),
		Name:         aws.String("consul-server"),
		NetworkInterfaces: []*ecs.NetworkInterface{
			{
				AttachmentId:       aws.String("7cb8f0b2-73ee-4893-840a-cda509e74d1f"),
				PrivateIpv4Address: aws.String(expectedIP),
			},
		},
		TaskArn: aws.String(taskARN),
	}
	serverTask := &ecs.Task{
		TaskArn:    aws.String(taskARN),
		Containers: []*ecs.Container{serverContainer},
	}
	return serverTask
}

type MockECS struct {
	ecsiface.ECSAPI

	IncompleteTasks []*ecs.Task
	CompleteTasks   []*ecs.Task

	onceFlags map[string]bool
}

// ListTasks returns Task ARNs from IncompleteTasks once, then from CompleteTasks forever after.
func (m *MockECS) ListTasks(_ *ecs.ListTasksInput) (*ecs.ListTasksOutput, error) {
	tasks := m.tasks("ListTasks")

	var taskARNs []*string
	for _, task := range tasks {
		taskARNs = append(taskARNs, task.TaskArn)
	}
	return &ecs.ListTasksOutput{TaskArns: taskARNs}, nil
}

// DescribeTasks returns IncompleteTasks once, then CompleteTasks forever after.
func (m *MockECS) DescribeTasks(describeTasksInput *ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
	tasks := m.tasks("DescribeTasks")
	return &ecs.DescribeTasksOutput{Tasks: tasks}, nil
}

func (m *MockECS) tasks(method string) []*ecs.Task {
	if m.onceFlags == nil {
		m.onceFlags = make(map[string]bool)
	}

	if !m.onceFlags[method] {
		m.onceFlags[method] = true
		return m.IncompleteTasks
	}
	return m.CompleteTasks
}
