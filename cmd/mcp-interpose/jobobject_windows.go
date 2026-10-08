//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObject          = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
)

// These mirror JOBOBJECT_BASIC_LIMIT_INFORMATION, IO_COUNTERS and
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION. Go lays the fields out with the same padding
// the C compiler does on the 64-bit targets we ship; on any layout where it does not,
// the size passed to the call would be wrong and the call fails rather than misreads.
type jobBasicLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobExtendedLimits struct {
	BasicLimitInformation jobBasicLimits
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// killChildrenOnExit puts this process in a job object that is configured to kill every
// process in it when the last handle to the job closes. Processes started afterwards,
// the wrapped server and everything it starts, join the job automatically, and the
// kernel closes our handle when we die, however we die: a normal exit, a crash, or the
// host's TerminateProcess, which gives us no chance to run any cleanup.
//
// The handle is deliberately never closed by us. Closing it is what does the killing.
// Failure is not fatal; the caller logs it and carries on without the guarantee.
func killChildrenOnExit() error {
	job, _, err := procCreateJobObject.Call(0, 0)
	if job == 0 {
		return fmt.Errorf("CreateJobObject: %w", err)
	}
	var info jobExtendedLimits
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if r, _, err := procSetInformationJobObject.Call(
		job, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
	); r == 0 {
		_ = syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("SetInformationJobObject: %w", err)
	}
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		_ = syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("GetCurrentProcess: %w", err)
	}
	if r, _, err := procAssignProcessToJobObject.Call(job, uintptr(self)); r == 0 {
		// Typically access denied: the host already put us in a job that forbids
		// nesting. The wrapped server then relies on terminate and on stdin closing.
		_ = syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}
