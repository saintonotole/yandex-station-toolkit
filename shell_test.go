package main

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

type testStdin struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *testStdin) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *testStdin) Close() error { return nil }

func (w *testStdin) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func TestShellWriteOrdered(t *testing.T) {
	s := &shellSession{stdin: &testStdin{}}
	s.startSeq(5)
	// Wails goroutines deliver out of order: 6 and 7 arrive before 5.
	s.writeOrdered("B", 6)
	s.writeOrdered("C", 7)
	if got := s.stdin.(*testStdin).String(); got != "" {
		t.Fatalf("early writes must not reach stdin, got %q", got)
	}
	s.writeOrdered("A", 5)
	if got := s.stdin.(*testStdin).String(); got != "ABC" {
		t.Fatalf("gap close must drain in order, got %q", got)
	}
	// Stale seq from a previous session is dropped.
	s.writeOrdered("X", 3)
	// Unsequenced writes pass straight through.
	s.writeOrdered("Z", 0)
	if got := s.stdin.(*testStdin).String(); got != "ABCZ" {
		t.Fatalf("stale/unsequenced handling wrong, got %q", got)
	}
}

func TestShellWriteOrderedConcurrent(t *testing.T) {
	s := &shellSession{stdin: &testStdin{}}
	s.startSeq(1)
	var wg sync.WaitGroup
	for i := 1; i <= 64; i++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			s.writeOrdered(string(rune('a'-1+seq)), seq)
		}(uint64(i))
	}
	wg.Wait()
	want := ""
	for i := 1; i <= 64; i++ {
		want += string(rune('a' - 1 + i))
	}
	if got := s.stdin.(*testStdin).String(); got != want {
		t.Fatalf("concurrent writes reordered: got %q", got)
	}
}

// io.Writer compatibility guard for the fake.
var _ io.WriteCloser = (*testStdin)(nil)
