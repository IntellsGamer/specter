//go:build !windows

package main

import (
	"log"
	"os"
	"os/exec"
	"runtime"
)

// notifyUser tries a GUI dialog when a display exists, else logs.
func notifyUser(title, msg string) {
	full := title + ": " + msg
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("osascript"); err == nil {
			exec.Command("osascript", "-e",
				`display dialog "`+msg+`" with title "`+title+`" buttons {"OK"} default button "OK"`).Run()
			return
		}
	}
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		if _, err := exec.LookPath("zenity"); err == nil {
			exec.Command("zenity", "--info", "--title="+title, "--text="+msg).Run()
			return
		}
	}
	log.Print(full)
}
