package notify

import (
	"github.com/nizartuanku/attack-surface-monitor/sched"
)

// BindScheduler wires a scheduler's results into the dispatcher: newly-open
// findings become "opened" events, auto-resolved ones become "resolved". This
// is the one line of glue a product binary needs:
//
//	notify.BindScheduler(s, dispatcher)
func BindScheduler(s *sched.Scheduler, d *Dispatcher) {
	prev := s.OnResult
	s.OnResult = func(r sched.Result) {
		if prev != nil {
			prev(r)
		}
		for _, f := range r.Reconcile.NewlyOpen {
			d.Enqueue(Event{Kind: KindOpened, Module: r.Module, Finding: f})
		}
		for _, f := range r.Reconcile.Resolved {
			d.Enqueue(Event{Kind: KindResolved, Module: r.Module, Finding: f})
		}
	}
}
