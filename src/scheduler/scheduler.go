package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
)

// Task represents a scheduled task
type Task struct {
	ID          string
	Name        string
	Schedule    string
	Handler     func(context.Context) error
	Enabled     bool
	LastRun     time.Time
	LastStatus  string
	LastError   string
	NextRun     time.Time
	RunCount    int
	FailCount   int
	RetryOnFail bool
	RetryDelay  time.Duration
	MaxRetries  int
}

// Scheduler manages scheduled tasks using gocron/v2.
type Scheduler struct {
	s        gocron.Scheduler
	tasks    map[string]*Task
	jobIDs   map[string]uuid.UUID
	mu       sync.RWMutex
	timezone *time.Location
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates a new Scheduler.
func New(timezone string) (*Scheduler, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	s, err := gocron.NewScheduler(gocron.WithLocation(loc))
	if err != nil {
		return nil, fmt.Errorf("creating gocron scheduler: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Scheduler{
		s:        s,
		tasks:    make(map[string]*Task),
		jobIDs:   make(map[string]uuid.UUID),
		timezone: loc,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// AddTask adds a task to the scheduler.
func (s *Scheduler) AddTask(task *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[task.ID]; exists {
		return fmt.Errorf("task %s already exists", task.ID)
	}

	if task.Enabled {
		t := task
		job, err := s.s.NewJob(
			gocron.CronJob(task.Schedule, false),
			gocron.NewTask(func() { s.runTask(t) }),
		)
		if err != nil {
			return fmt.Errorf("invalid schedule %s: %w", task.Schedule, err)
		}
		s.jobIDs[task.ID] = job.ID()
	}

	s.tasks[task.ID] = task
	return nil
}

// RemoveTask removes a task from the scheduler.
func (s *Scheduler) RemoveTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[taskID]; !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	if jobID, ok := s.jobIDs[taskID]; ok {
		s.s.RemoveJob(jobID)
		delete(s.jobIDs, taskID)
	}

	delete(s.tasks, taskID)
	return nil
}

// GetTask returns a task by ID.
func (s *Scheduler) GetTask(taskID string) (*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return nil, fmt.Errorf("task %s not found", taskID)
	}

	return task, nil
}

// GetAllTasks returns all registered tasks.
func (s *Scheduler) GetAllTasks() []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}

	return tasks
}

// RunTaskNow triggers immediate execution of a task.
func (s *Scheduler) RunTaskNow(taskID string) error {
	s.mu.RLock()
	task, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	go s.runTask(task)
	return nil
}

// runTask executes a task handler with timeout and updates its status.
func (s *Scheduler) runTask(task *Task) {
	if !task.Enabled {
		return
	}

	task.LastRun = time.Now()

	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()

	err := task.Handler(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		task.LastStatus = "failed"
		task.LastError = err.Error()
		task.FailCount++

		if task.RetryOnFail && task.FailCount < task.MaxRetries {
			go s.retryTask(task)
		}
	} else {
		task.LastStatus = "success"
		task.LastError = ""
		task.RunCount++
		task.FailCount = 0
	}
}

// retryTask retries a failed task after the configured delay.
func (s *Scheduler) retryTask(task *Task) {
	time.Sleep(task.RetryDelay)

	if task.FailCount < task.MaxRetries {
		s.runTask(task)
	}
}

// Start starts the scheduler.
func (s *Scheduler) Start() {
	s.s.Start()
}

// Stop stops the scheduler gracefully.
func (s *Scheduler) Stop() {
	s.cancel()
	s.s.Shutdown()
}

// EnableTask enables a task by ID.
func (s *Scheduler) EnableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	task.Enabled = true
	return nil
}

// DisableTask disables a task by ID.
func (s *Scheduler) DisableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	task.Enabled = false
	return nil
}

// GetStatus returns a summary of scheduler state.
func (s *Scheduler) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	taskStatuses := make([]map[string]interface{}, 0, len(s.tasks))
	for _, task := range s.tasks {
		taskStatuses = append(taskStatuses, map[string]interface{}{
			"id":          task.ID,
			"name":        task.Name,
			"enabled":     task.Enabled,
			"last_run":    task.LastRun,
			"last_status": task.LastStatus,
			"last_error":  task.LastError,
			"next_run":    task.NextRun,
			"run_count":   task.RunCount,
			"fail_count":  task.FailCount,
		})
	}

	return map[string]interface{}{
		"timezone": s.timezone.String(),
		"tasks":    taskStatuses,
	}
}
