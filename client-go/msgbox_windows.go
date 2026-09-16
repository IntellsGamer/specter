//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	modUser32     = syscall.NewLazyDLL("user32.dll")
	procMessageBox = modUser32.NewProc("MessageBoxW")
)

// notifyUser pops a GUI message box when a display is available.
// Console fallback is handled by the caller via log output.
func notifyUser(title, msg string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(m)), 0x40)
}
