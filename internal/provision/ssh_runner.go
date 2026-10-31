package provision

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHRunner struct {
	Client *ssh.Client
}

func (r *SSHRunner) Shell(ctx context.Context, cmd string) (string, error) {
	sess, err := r.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %v", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func (r *SSHRunner) Push(ctx context.Context, local, remote string) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()

	sess, err := r.Client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %v", err)
	}
	defer sess.Close()
	// Remote paths stay slash-separated. filepath.Dir on Windows turns
	// /data/opt/bin into \data\opt\bin, and the station shell eats those
	// backslashes, so mkdir runs as "dataoptbin" on the read-only root.
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, f)
		_ = stdin.Close()
	}()
	out, err := sess.CombinedOutput(pushCommand(remote))
	if err != nil {
		return fmt.Errorf("ssh push %s: %v: %s", filepath.Base(local), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pushCommand writes remote.new and renames it over remote. On this speaker /data is a symlink to the writable /bkupgrade/data
// partition, and dropbear runs from /data/opt/bin/dropbearmulti.
// Opening that path for write fails with ETXTBSY ("Text file busy")
// while the listener — and this SSH session — still have it mapped.
// rename does not, and the running process keeps the old inode.
func pushCommand(remote string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	dir := path.Dir(remote)
	tmp := remote + ".new"
	return fmt.Sprintf("mkdir -p %s && cat > %s && chmod 755 %s && mv -f %s %s", q(dir), q(tmp), q(tmp), q(tmp), q(remote))
}

func (r *SSHRunner) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}
	return nil
}
