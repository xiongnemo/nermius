//go:build windows

package service

import (
	"net"
	"os"
	"strings"

	"github.com/Microsoft/go-winio"
)

func dialAgent(socket string) (net.Conn, error) {
	if socket == "" {
		socket = os.Getenv("SSH_AUTH_SOCK")
	}
	if socket == "" {
		socket = `\\.\pipe\openssh-ssh-agent`
	}
	if strings.HasPrefix(socket, `\\.\pipe\`) {
		return winio.DialPipe(socket, nil)
	}
	return net.Dial("unix", socket)
}
