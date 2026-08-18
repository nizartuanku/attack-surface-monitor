// asm is the Attack Surface Monitor product binary: ASM on Sentinel Core.
//
//	asm                     # dashboard on 127.0.0.1:8423
//	asm -db asm.db          # SQLite path (default)
//
// Add a domain, follow the verification instructions, and once ownership is
// proven ASM discovers and monitors your external attack surface.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/attack-surface-monitor/asm"
	"github.com/nizartuanku/attack-surface-monitor/license"
	"github.com/nizartuanku/attack-surface-monitor/notify"
	"github.com/nizartuanku/attack-surface-monitor/sched"
	"github.com/nizartuanku/attack-surface-monitor/store"
	"github.com/nizartuanku/attack-surface-monitor/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// asmTierLimits is ASM's own per-tier table: free = 1 verified domain, Pro = 10,
// Team = unlimited. This overrides the license package's global defaults, which
// are CertWatch's numbers.
var asmTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 1, RetentionDays: 14, Channels: []string{"webhook"}},
	license.TierPro: {MaxTargets: 10, RetentionDays: 365,
		Channels: []string{"webhook", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8423", "dashboard listen address")
	dbPath := flag.String("db", "asm.db", "SQLite database path")
	licFile := flag.String("license", "asm-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for notifications")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	verifyStore, err := store.NewSQLiteVerifyStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	module := asm.New(verifyStore)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}

	// Restore saved domains before Start (verification state persists too).
	if saved, err := st.ListSavedTargets(module.Describe().ID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(module.Describe().ID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "asm: skipping saved domain %q: %v\n", raw, err)
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = asmTierLimits
	server.Verify = verifyStore

	if *webhook != "" {
		disp := notify.NewDispatcher(notify.Config{}, &notify.WebhookChannel{URL: *webhook})
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("Attack Surface Monitor %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "asm: "+msg)
	os.Exit(1)
}
