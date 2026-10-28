package notify

import (
	"context"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/hfsbridge"
	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"
)

// HFSChannel delivers digests as Hexward Finding Schema events through any
// hexward-core sink: an NDJSON file, syslog in JSON or CEF, a Splunk HTTP
// Event Collector, or webhook v2. Unlike the digest-shaped webhook v1, every
// event carries the finding's fingerprint, id and timestamps, so a SIEM can
// deduplicate and correlate without guessing.
type HFSChannel struct {
	Sink    sink.Sink
	Meta    hfs.Meta // Product may be left empty: the digest's module is used
	Options hfs.Options
}

func (c *HFSChannel) Name() string { return c.Sink.Name() }

func (c *HFSChannel) Send(ctx context.Context, d Digest) error {
	if d.Empty() {
		return nil
	}
	return c.Sink.Send(ctx, Events(c.Meta, d, c.Options))
}

// Events converts one digest into HFS events: opened findings first (the
// digest already orders them most severe first), then resolved ones.
func Events(meta hfs.Meta, d Digest, opt hfs.Options) []hfs.Event {
	if meta.Product == "" {
		meta.Product = d.Module
	}
	at := d.At
	if at.IsZero() {
		at = time.Now()
	}
	out := make([]hfs.Event, 0, len(d.Opened)+len(d.Resolved))
	for _, f := range d.Opened {
		out = append(out, hfs.New(hfs.KindOpened, meta, hfsbridge.Source(f), at, opt))
	}
	for _, f := range d.Resolved {
		out = append(out, hfs.New(hfs.KindResolved, meta, hfsbridge.Source(f), at, opt))
	}
	return out
}
