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

		_ = syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}
