package provision

import (
	"fmt"
	"os"
	"strings"
)

func defaultTempDir() string {
	d, err := os.MkdirTemp("", "yandex-station-toolkit-*")
	if err != nil {
		return os.TempDir()
	}
	return d
}

type SSHOpts struct {
	Port               int
	AllowBlankPassword bool // -B (blank root password) instead of -s (key-only)
}

func DefaultSSHOpts() SSHOpts { return SSHOpts{Port: 2222} }

// BuildInitScript points dropbear at its own authorized_keys directory via
// -D, so logins never depend on root's home directory or any key sync.
func BuildInitScript(opts SSHOpts) []byte {
	if opts.Port == 0 {
		opts.Port = 2222
	}
	authFlag := "-s"
	authTag := "key-only"
	if opts.AllowBlankPassword {
		authFlag = "-B"
		authTag = "insecure"
	}
	const tmpl = `#!/bin/sh
# Autostart dropbear SSH on :__PORT__, __AUTHTAG__ (installed by Yandex Station ToolKit).
# Remove this file to uninstall. Keys live in /data/opt/etc/dropbear.
DB=/data/opt/bin/dropbear
DIR=/data/opt/etc/dropbear
HK=$DIR/hk_ed25519
LOG=$DIR/dropbear.log

start() {
  [ -x "$DB" ] || { echo "$(date) no $DB" >> "$LOG"; return 1; }
  # host key lost (e.g. /data wiped) -> make a new one
  [ -s "$HK" ] || /data/opt/bin/dropbearkey -t ed25519 -f "$HK" >> "$LOG" 2>&1 || return 1
  pidof dropbear >/dev/null 2>&1 && return 0
  # __AUTHTAG__ (password logins disabled → key-only,
  # or blank-password root login allowed). -D points dropbear at
  # $DIR/authorized_keys directly, independent of any user's home
  # directory. This build has no syslog: messages go to stderr, i.e.
  # to $LOG.
  "$DB" -r "$HK" -D "$DIR" -p __PORT__ __AUTHFLAG__ 2>>"$LOG"
}
case "$1" in
  start)   start ;;
  stop)    killall dropbear 2>/dev/null ;;
  restart) killall dropbear 2>/dev/null; sleep 1; start ;;
esac
exit 0
`
	out := strings.ReplaceAll(tmpl, "__PORT__", fmt.Sprintf("%d", opts.Port))
	out = strings.ReplaceAll(out, "__AUTHFLAG__", authFlag)
	out = strings.ReplaceAll(out, "__AUTHTAG__", authTag)
	return []byte(out)
}

// ParseInitScript returns ok=false for scripts this tool did not write.
func ParseInitScript(content string) (opts SSHOpts, ok bool) {
	if !strings.Contains(content, "dropbear") {
		return SSHOpts{}, false
	}
	// Comment lines may mention the flags literally; only the invocation counts.
	dropLine := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if strings.Contains(line, "\"$DB\"") || strings.Contains(line, "/data/opt/bin/dropbear") {
			if strings.Contains(line, "-r") || strings.Contains(line, "-p") {
				dropLine = line
				break
			}
		}
	}
	if dropLine == "" {
		return SSHOpts{}, false
	}
	if i := strings.Index(dropLine, "-p "); i >= 0 {
		fmt.Sscanf(dropLine[i+3:], "%d", &opts.Port)
	}
	if opts.Port <= 0 {
		opts.Port = 2222
	}
	switch {
	case strings.Contains(dropLine, " -B"):
		opts.AllowBlankPassword = true
	case strings.Contains(dropLine, " -s"):
		opts.AllowBlankPassword = false
	default:
		return SSHOpts{}, false
	}
	return opts, true
}
