package main

import (
	"testing"
	"time"
)

func ip32(a, b, c, d uint32) uint32 {
	return a | b<<8 | c<<16 | d<<24 // little-endian, same as the datapath
}

// Two peers reporting the same pod: the aggregate is their sum.
func TestSyncerAggregatesAcrossPeers(t *testing.T) {
	s := newSyncer(nil)
	x := ip32(10, 0, 0, 1)

	_ = s.apply("a", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("a", &ValueRequest{Key: int32(x), Value: 3, Type: kvSet, Mapid: 1})
	_ = s.apply("b", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("b", &ValueRequest{Key: int32(x), Value: 4, Type: kvSet, Mapid: 1})

	if got := s.written[x]; got != 7 {
		t.Fatalf("written[%s] = %d, want 7", u32ToIP(x), got)
	}
}

// A new epoch replaces a publisher's whole table: entries absent from the new
// snapshot must disappear.
func TestSyncerNewEpochDropsOldEntries(t *testing.T) {
	s := newSyncer(nil)
	x, y := ip32(10, 0, 0, 1), ip32(10, 0, 0, 2)

	_ = s.apply("a", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("a", &ValueRequest{Key: int32(x), Value: 2, Type: kvSet, Mapid: 1})
	_ = s.apply("a", &ValueRequest{Key: int32(y), Value: 5, Type: kvSet, Mapid: 1})
	if s.written[x] != 2 || s.written[y] != 5 {
		t.Fatalf("initial aggregate wrong: %v", s.written)
	}

	_ = s.apply("a", &ValueRequest{Type: snapshotBegin, Mapid: 2})
	_ = s.apply("a", &ValueRequest{Key: int32(x), Value: 1, Type: kvSet, Mapid: 2})

	if got := s.written[x]; got != 1 {
		t.Fatalf("written[%s] = %d, want 1", u32ToIP(x), got)
	}
	if _, ok := s.written[y]; ok {
		t.Fatalf("entry %s should have been dropped on epoch change", u32ToIP(y))
	}
}

// Evicting a silent peer subtracts its contribution only.
func TestSyncerEvictStale(t *testing.T) {
	s := newSyncer(nil)
	x := ip32(10, 0, 0, 1)

	_ = s.apply("a", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("a", &ValueRequest{Key: int32(x), Value: 3, Type: kvSet, Mapid: 1})
	_ = s.apply("b", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("b", &ValueRequest{Key: int32(x), Value: 2, Type: kvSet, Mapid: 1})

	s.mu.Lock()
	s.peers["a"].seen = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	s.evictStale(time.Minute)
	if got := s.written[x]; got != 2 {
		t.Fatalf("after evicting a: written = %d, want 2", got)
	}

	s.mu.Lock()
	s.peers["b"].seen = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	s.evictStale(time.Minute)
	if _, ok := s.written[x]; ok {
		t.Fatalf("expected %s removed after all peers evicted", u32ToIP(x))
	}
}

// reconcileAll must not change a consistent aggregate.
func TestSyncerReconcileAllNoop(t *testing.T) {
	s := newSyncer(nil)
	x := ip32(10, 0, 0, 1)
	_ = s.apply("a", &ValueRequest{Type: snapshotBegin, Mapid: 1})
	_ = s.apply("a", &ValueRequest{Key: int32(x), Value: 9, Type: kvSet, Mapid: 1})

	s.reconcileAll()
	if got := s.written[x]; got != 9 {
		t.Fatalf("written = %d, want 9", got)
	}
}

func TestSyncerUnknownType(t *testing.T) {
	s := newSyncer(nil)
	if err := s.apply("a", &ValueRequest{Type: 99}); err == nil {
		t.Fatal("expected an error for an unknown message type")
	}
}
