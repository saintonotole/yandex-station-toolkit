package provision

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// AliceVocalize dials the (already tunneled) IPC address and speaks the
// phrase over it.
func AliceVocalize(ctx context.Context, addr, text string, timeout time.Duration, log Logger) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("vocalize: the phrase is empty")
	}
	if timeout < 3*time.Second {
		timeout = 3 * time.Second
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("vocalize: ipc dial %s: %v", addr, err)
	}
	defer conn.Close()
	return AliceVocalizeConn(ctx, conn, text, timeout, log)
}

// AliceVocalizeConn speaks the phrase over an established connection to
// the station's local quasar IPC (127.0.0.1:9875 on the device — tunneled
// here over adb forward or an SSH channel). Wire format per the wiki's
// verified recipe: uint32 little-endian length + a Remoting protobuf
// envelope; AliceCapability, START_VOCALIZE (18) with a TVocalizeDirective
// (text, Append mode). Events, verified on a live speaker: pushes carry
// the Alice voice state in remote field 1 (2 = speaking, 0 = idle), and
// responses on our request marker carry the lifecycle in remote field 18
// (nested 1 = 6 accepted with a session id, nested 1 = 1 completed,
// 4 = a speech-service error). Synthesis happens in the Yandex cloud
// with the station's own session — the station needs internet.
//
// A timeout is "no confirmation", not proof of silence: the phrase may
// still play after the deadline.
func AliceVocalizeConn(ctx context.Context, conn net.Conn, text string, timeout time.Duration, log Logger) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("vocalize: the phrase is empty")
	}
	if timeout < 3*time.Second {
		timeout = 3 * time.Second
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// The subscription and the request share one live IPC connection.
	if _, err := conn.Write(append(subscribeFrame(), vocalizeFrame(text)...)); err != nil {
		return fmt.Errorf("vocalize: send: %v", err)
	}
	log.Logf("tts: phrase sent, waiting for the speech events")

	started := false
	buf := make([]byte, 4)
	for {
		if _, err := readFull(conn, buf); err != nil {
			if started {
				// The phrase played; the connection closing without an
				// explicit idle push is how some firmware generations end.
				log.Logf("tts: the phrase finished playing (connection closed)")
				return nil
			}
			return fmt.Errorf("vocalize: the ipc connection closed before the speech was confirmed")
		}
		size := int(binary.LittleEndian.Uint32(buf))
		if size <= 0 || size > 512*1024 {
			return fmt.Errorf("vocalize: bad frame size %d", size)
		}
		payload := make([]byte, size)
		if _, err := readFull(conn, payload); err != nil {
			if started {
				log.Logf("tts: the phrase finished playing (connection closed)")
				return nil
			}
			return fmt.Errorf("vocalize: the ipc connection closed mid-frame")
		}
		env, err := parseFields(payload)
		if err != nil {
			continue
		}
		marker, _ := env[253].(uint64)
		remoteBytes, ok := env[252].([]byte)
		if !ok {
			continue
		}
		// Pushes (marker 3) carry the Alice voice state in remote field 1:
		// 0 = idle, 2 = speaking. The user-audible truth of the phrase.
		if marker == 3 {
			remote, err := parseFields(remoteBytes)
			if err != nil {
				continue
			}
			state, _ := remote[1].(uint64)
			switch state {
			case 2:
				if !started {
					started = true
					log.Logf("tts: the phrase is being spoken")
				}
			case 0:
				if started {
					log.Logf("tts: the phrase finished playing")
					return nil
				}
			}
			continue
		}
		// Responses (our request marker 210) carry the vocalize lifecycle
		// in remote field 18: nested field 1 = 6 with a session id when
		// the request is accepted, 1 when the utterance completes.
		remote, err := parseFields(remoteBytes)
		if err != nil {
			continue
		}
		evBytes, ok := remote[18].([]byte)
		if !ok {
			continue
		}
		events, err := parseFields(evBytes)
		if err != nil {
			continue
		}
		code, ok := events[1].(uint64)
		if !ok {
			continue
		}
		switch code {
		case 6:
			log.Logf("tts: the vocalize request was accepted")
		case 1:
			if started {
				log.Logf("tts: the phrase finished playing")
				return nil
			}
		case 4: // ON_ALICE_ERROR — never log private event payloads.
			return fmt.Errorf("vocalize: the speech service reported an error")
		}
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func putVarint(b []byte, v uint64) []byte {
	for v >= 128 {
		b = append(b, byte(v)|128)
		v >>= 7
	}
	return append(b, byte(v))
}

func varint(v uint64) []byte { return putVarint(nil, v) }

func intField(field int, v uint64) []byte {
	return append(varint(uint64(field)*8), varint(v)...)
}

func bytesField(field int, value []byte) []byte {
	out := varint(uint64(field)*8 + 2)
	out = putVarint(out, uint64(len(value)))
	return append(out, value...)
}

// parseFields reads a small protobuf envelope; truncated or unsupported
// fields surface as errors, and the caller treats those as noise.
func parseFields(data []byte) (map[int]any, error) {
	out := map[int]any{}
	offset := 0
	readVarint := func() (uint64, error) {
		var v uint64
		for shift := uint(0); shift < 70; shift += 7 {
			if offset >= len(data) {
				return 0, fmt.Errorf("truncated varint")
			}
			b := data[offset]
			offset++
			v |= uint64(b&127) << shift
			if b < 128 {
				return v, nil
			}
			if shift == 63 && b > 1 {
				return 0, fmt.Errorf("bad varint")
			}
		}
		return 0, fmt.Errorf("bad varint")
	}
	for offset < len(data) {
		key, err := readVarint()
		if err != nil {
			return nil, err
		}
		field := key >> 3
		wire := key & 7
		switch wire {
		case 0:
			v, err := readVarint()
			if err != nil {
				return nil, err
			}
			out[int(field)] = v
		case 2:
			size, err := readVarint()
			if err != nil {
				return nil, err
			}
			if offset+int(size) > len(data) {
				return nil, fmt.Errorf("truncated field")
			}
			out[int(field)] = append([]byte(nil), data[offset:offset+int(size)]...)
			offset += int(size)
		case 1:
			if offset+8 > len(data) {
				return nil, fmt.Errorf("truncated fixed64")
			}
			offset += 8
		case 5:
			if offset+4 > len(data) {
				return nil, fmt.Errorf("truncated fixed32")
			}
			offset += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return out, nil
}

// rpcFrame wraps a payload in the Remoting envelope: the AliceCapability
// remote in field 252, the request marker 210 in field 253, framed by a
// uint32 little-endian length.
func rpcFrame(field int, payload []byte) []byte {
	remote := append(bytesField(7, []byte("AliceCapability")), bytesField(field, payload)...)
	envelope := append(bytesField(252, remote), intField(253, 210)...)
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(envelope)))
	return append(out, envelope...)
}

func subscribeFrame() []byte {
	return rpcFrame(20, bytesField(1, []byte("AliceCapability")))
}

func vocalizeFrame(text string) []byte {
	// START_VOCALIZE=18, events=true, TVocalizeDirective(text, Append=1).
	directive := append(bytesField(1, []byte(text)), intField(2, 1)...)
	return rpcFrame(8, append(append(intField(1, 18), intField(3, 1)...), bytesField(13, directive)...))
}
