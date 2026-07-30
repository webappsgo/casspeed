package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

// noopHandler is a task handler that always succeeds immediately.
func noopHandler(_ context.Context) error { return nil }

// failHandler is a task handler that always returns an error.
func failHandler(_ context.Context) error { return errors.New("task failed") }

// ---- New tests -----------------------------------------------------------

func TestNew_ValidTimezone(t *testing.T) {
	s, err := New("UTC")
	if err != nil {
		t.Fatalf("New(UTC) error: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil")
	}
	s.Stop()
}

func TestNew_InvalidTimezoneDefaultsToUTC(t *testing.T) {
	// Invalid timezone should not return an error; it silently falls back to UTC.
	s, err := New("Invalid/Timezone")
	if err != nil {
		t.Fatalf("unexpected error for invalid timezone: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil for invalid timezone")
	}
	s.Stop()
}

// ---- AddTask tests -------------------------------------------------------

func TestAddTask_Success(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	task := &Task{
		ID:       "t1",
		Name:     "Test Task",
		Schedule: "@hourly",
		Handler:  noopHandler,
		Enabled:  true,
	}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask error: %v", err)
	}
}

func TestAddTask_Duplicate(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	task := &Task{ID: "t1", Schedule: "@hourly", Handler: noopHandler, Enabled: false}
	s.AddTask(task)
	err := s.AddTask(task)
	if err == nil {
		t.Error("expected error when adding duplicate task ID")
	}
}

func TestAddTask_InvalidSchedule(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	task := &Task{
		ID:       "bad",
		Schedule: "not-a-cron-expr",
		Handler:  noopHandler,
		Enabled:  true,
	}
	if err := s.AddTask(task); err == nil {
		t.Error("expected error for invalid cron schedule")
	}
}

func TestAddTask_DisabledSkipsCronRegistration(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	// Even with invalid schedule, disabled task should not parse the schedule.
	task := &Task{
		ID:       "disabled",
		Schedule: "not-a-valid-schedule",
		Handler:  noopHandler,
		Enabled:  false,
	}
	if err := s.AddTask(task); err != nil {
		t.Errorf("disabled task with invalid schedule should not fail: %v", err)
	}
}

// ---- RemoveTask tests ----------------------------------------------------

func TestRemoveTask_Success(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	task := &Task{ID: "t1", Schedule: "@hourly", Handler: noopHandler, Enabled: false}
	s.AddTask(task)

	if err := s.RemoveTask("t1"); err != nil {
		t.Fatalf("RemoveTask error: %v", err)
	}
	if _, err := s.GetTask("t1"); err == nil {
		t.Error("task should be gone after removal")
	}
}

func TestRemoveTask_NotFound(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	if err := s.RemoveTask("nonexistent"); err == nil {
		t.Error("expected error removing nonexistent task")
	}
}

// ---- GetTask tests -------------------------------------------------------

func TestGetTask_Found(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	task := &Task{ID: "t1", Name: "My Task", Schedule: "@hourly", Handler: noopHandler, Enabled: false}
	s.AddTask(task)

	got, err := s.GetTask("t1")
	if err != nil {
		t.Fatalf("GetTask error: %v", err)
	}
	if got.Name != "My Task" {
		t.Errorf("Name = %q, want 'My Task'", got.Name)
	}
}

func TestGetTask_NotFound(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	_, err := s.GetTask("missing")
	if err == nil {
		t.Error("expected error for missing task")
	}
}

// ---- GetAllTasks tests ---------------------------------------------------

func TestGetAllTasks_Empty(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	tasks := s.GetAllTasks()
	if len(tasks) != 0 {
		t.Errorf("GetAllTasks() = %d, want 0", len(tasks))
	}
}

func TestGetAllTasks_MultipleTasksReturned(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	for _, id := range []string{"a", "b", "c"} {
		s.AddTask(&Task{ID: id, Schedule: "@hourly", Handler: noopHandler, Enabled: false})
	}
	tasks := s.GetAllTasks()
	if len(tasks) != 3 {
		t.Errorf("GetAllTasks() returned %d tasks, want 3", len(tasks))
	}
}

// ---- EnableTask / DisableTask tests --------------------------------------

func TestEnableTask_Success(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	s.AddTask(&Task{ID: "t1", Schedule: "@hourly", Handler: noopHandler, Enabled: false})
	if err := s.EnableTask("t1"); err != nil {
		t.Fatalf("EnableTask error: %v", err)
	}
	task, _ := s.GetTask("t1")
	if !task.Enabled {
		t.Error("task should be enabled after EnableTask")
	}
}

func TestDisableTask_Success(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	s.AddTask(&Task{ID: "t1", Schedule: "@hourly", Handler: noopHandler, Enabled: false})
	s.EnableTask("t1")
	if err := s.DisableTask("t1"); err != nil {
		t.Fatalf("DisableTask error: %v", err)
	}
	task, _ := s.GetTask("t1")
	if task.Enabled {
		t.Error("task should be disabled after DisableTask")
	}
}

func TestEnableTask_NotFound(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	if err := s.EnableTask("missing"); err == nil {
		t.Error("expected error enabling nonexistent task")
	}
}

func TestDisableTask_NotFound(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	if err := s.DisableTask("missing"); err == nil {
		t.Error("expected error disabling nonexistent task")
	}
}

// ---- RunTaskNow tests ----------------------------------------------------

func TestRunTaskNow_Success(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	ran := make(chan struct{}, 1)
	task := &Task{
		ID:       "t1",
		Schedule: "@hourly",
		Enabled:  true,
		Handler: func(_ context.Context) error {
			ran <- struct{}{}
			return nil
		},
	}
	s.AddTask(task)

	if err := s.RunTaskNow("t1"); err != nil {
		t.Fatalf("RunTaskNow error: %v", err)
	}

	select {
	case <-ran:
		// success
	case <-time.After(2 * time.Second):
		t.Error("task handler was not called within timeout")
	}
}

func TestRunTaskNow_NotFound(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	if err := s.RunTaskNow("missing"); err == nil {
		t.Error("expected error for nonexistent task")
	}
}

// ---- GetStatus tests -----------------------------------------------------

func TestGetStatus_ContainsTimezoneAndTasks(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	s.AddTask(&Task{ID: "t1", Name: "status-test", Schedule: "@hourly", Handler: noopHandler, Enabled: false})

	status := s.GetStatus()
	if _, ok := status["timezone"]; !ok {
		t.Error("GetStatus() missing 'timezone' key")
	}
	if _, ok := status["tasks"]; !ok {
		t.Error("GetStatus() missing 'tasks' key")
	}
}

// ---- runTask sets LastStatus on success/failure --------------------------

func TestRunTask_SuccessUpdatesStatus(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	done := make(chan struct{}, 1)
	task := &Task{
		ID:       "t1",
		Schedule: "@hourly",
		Enabled:  true,
		Handler: func(_ context.Context) error {
			return nil
		},
	}
	s.AddTask(task)

	go func() {
		s.runTask(task)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runTask timed out")
	}

	if task.LastStatus != "success" {
		t.Errorf("LastStatus = %q, want 'success'", task.LastStatus)
	}
	if task.RunCount != 1 {
		t.Errorf("RunCount = %d, want 1", task.RunCount)
	}
}

func TestRunTask_FailureUpdatesStatus(t *testing.T) {
	s, _ := New("UTC")
	defer s.Stop()

	done := make(chan struct{}, 1)
	task := &Task{
		ID:       "t2",
		Schedule: "@hourly",
		Enabled:  true,
		Handler:  failHandler,
	}
	s.AddTask(task)

	go func() {
		s.runTask(task)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runTask timed out")
	}

	if task.LastStatus != "failed" {
		t.Errorf("LastStatus = %q, want 'failed'", task.LastStatus)
	}
	if task.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", task.FailCount)
	}
}
