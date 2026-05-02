package schedplan

import (
	"log"
	"time"
)

// FireFunc is called when a scheduled plan fires. The schedule is a value copy.
type FireFunc func(sc *Schedule)

// Runner polls the Store every 30 seconds and fires due schedules.
type Runner struct {
	store  *Store
	fire   FireFunc
	ticker *time.Ticker
	done   chan struct{}
}

func NewRunner(store *Store, fire FireFunc) *Runner {
	return &Runner{
		store: store,
		fire:  fire,
		done:  make(chan struct{}),
	}
}

func (r *Runner) Start() {
	r.ticker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-r.ticker.C:
				r.poll()
			case <-r.done:
				r.ticker.Stop()
				return
			}
		}
	}()
}

func (r *Runner) Stop() {
	close(r.done)
}

func (r *Runner) poll() {
	for _, sc := range r.store.Due() {
		sc := sc
		r.store.MarkRunning(sc.ID)
		go func() {
			log.Printf("[SCHEDPLAN] firing %s → %s (profile: %s)", sc.Name, sc.Target, sc.ProfileName)
			defer func() {
				if p := recover(); p != nil {
					log.Printf("[SCHEDPLAN] panic for %s: %v", sc.ID, p)
					r.store.MarkComplete(sc.ID, "error")
				}
			}()
			r.fire(sc)
			r.store.MarkComplete(sc.ID, "ok")
		}()
	}
}
