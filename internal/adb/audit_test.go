package adb

import "testing"

func TestAuditCommand(t *testing.T) {
	got := auditCommand([]string{"connect", "192.168.178.63:5555"})
	if got != "adb connect 192.168.178.63:5555" {
		t.Fatalf("connect: %q", got)
	}

	got = auditCommand([]string{"-s", "192.168.178.63:5555", "shell", "s=no; r=no\n[ -x /etc/init.d/S99zadbd ] && s=yes\necho \"script=$s\""})
	want := "adb shell 192.168.178.63:5555\n" +
		"  s=no\n" +
		"  r=no\n" +
		"  [ -x /etc/init.d/S99zadbd ] && s=yes\n" +
		"  echo \"script=$s\""
	if got != want {
		t.Fatalf("shell:\n%s\nwant:\n%s", got, want)
	}

	got = auditCommand([]string{"-s", "192.168.178.63:5555", "shell", "echo 'a;b'"})
	if got != "adb shell 192.168.178.63:5555\n  echo 'a;b'" {
		t.Fatalf("quoted semicolon split: %q", got)
	}

	got = auditCommand([]string{"-s", "192.168.178.63:5555", "push", "/tmp/dropbearmulti", "/data/opt/bin/dropbearmulti"})
	if got != "adb push 192.168.178.63:5555 dropbearmulti -> /data/opt/bin/dropbearmulti" {
		t.Fatalf("push: %q", got)
	}
}
