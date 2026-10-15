package ticket

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 13, 12, 30, 45, 123456000, time.UTC)
	id := uuid.New()

	got, err := decodeCursor(encodeCursor(ts, id))
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if !got.createdAt.Equal(ts) || got.id != id {
		t.Fatalf("cursor = %+v, want %v / %v", got, ts, id)
	}
}

func TestDecodeCursorRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"not base64 !!",
		"bm9waXBl",         // "nopipe"
		"YXxiYw",           // "a|bc": bad time
		"MjAyNi0xMC0xM3xi", // valid-looking time part cut off: bad time
	} {
		if _, err := decodeCursor(bad); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("decodeCursor(%q) error = %v, want ErrInvalidCursor", bad, err)
		}
	}
}
