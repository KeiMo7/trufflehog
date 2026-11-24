package gcs

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// unitProgress accumulates how far one unit's scan has got and publishes it on
// the source's Progress under the unit's ID, so the job report can show item
// progress inside a unit without mixing it with any other unit's counts.
//
// The totals are counted from the listing as it streams, never from a set of
// object names held in memory. Objects an exclude rule removes are not counted
// at all, so the unit's stats only ever describe objects the unit covers.
type unitProgress struct {
	unitID   string
	progress *sources.Progress

	mu       sync.Mutex
	items    sources.UnitProgress
	finished bool
}

func newUnitProgress(unitID string, progress *sources.Progress) *unitProgress {
	p := &unitProgress{
		unitID:   unitID,
		progress: progress,
		items:    sources.UnitProgress{State: sources.UnitProgressCounting},
	}
	p.publish()
	return p
}

// publish writes the current value under the lock, so an older update can never
// overwrite a newer one.
func (p *unitProgress) publish() {
	if p.progress == nil {
		return
	}
	p.progress.SetUnitProgressFor(p.unitID, p.items)
}

// addTotal records that an object belongs to the unit's scope, with the bytes it
// would contribute once read.
func (p *unitProgress) addTotal(size int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.items.ItemsTotal++
	if size > 0 {
		p.items.BytesTotal += uint64(size)
	}
	p.publish()
}

// objectDone records that an object was processed without a read failure, with
// the number of bytes it contributed. An object skipped as a duplicate passes
// 0 because its content was already counted when the earlier copy was read.
func (p *unitProgress) objectDone(size int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.items.ItemsDone++
	if size > 0 {
		p.items.BytesDone += uint64(size)
	}
	p.publish()
}

// finish settles the state. A unit only reports Ready when it covered its scope;
// one cut short reports Unavailable so nothing reads its totals as final.
func (p *unitProgress) finish(complete bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.finished = true
	if complete {
		p.items.State = sources.UnitProgressReady
	} else {
		p.items.State = sources.UnitProgressUnavailable
	}
	p.publish()
}
