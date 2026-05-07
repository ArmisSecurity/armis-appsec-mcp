// Imported package: executes shell command with unsanitized filename
package handler

import "os/exec"

func ProcessFile(filename string) error {
	cmd := exec.Command("sh", "-c", "convert "+filename+" output.pdf")
	return cmd.Run()
}
