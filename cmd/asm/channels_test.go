package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nizartuanku/attack-surface-monitor/notify"
	"github.com/nizartuanku/hexward-core/hfs"
)

func parse(t *testing.T, args ...string) *channelFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := registerChannelFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return c
}

func names(chs []notify.Channel) string {
	var out []string
	for _, c := range chs {
		out = append(out, c.Name())
	}
	return strings.Join(out, ",")
}

func TestChannelsDefaultsUnchanged(t *testing.T) {
	chs, err := parse(t).build(hfs.Meta{})
	if err != nil || len(chs) != 0 {
		t.Fatalf("no flags must mean no channels: %v %v", chs, err)
	}
	chs, err = parse(t, "-webhook", "http://x/h", "-syslog", "127.0.0.1:5514").build(hfs.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(chs); got != "webhook,syslog" {
		t.Fatalf("existing flags must keep the original channels, got %s", got)
	}
}

func TestChannelsAllSinks(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "hec.token")
	sec := filepath.Join(dir, "wh.secret")
	os.WriteFile(tok, []byte("abc\n"), 0o600)
	os.WriteFile(sec, []byte("s3\n"), 0o600)
	chs, err := parse(t,
		"-webhook", "http://x/h", "-webhook-format", "v2", "-webhook-secret-file", sec,
		"-syslog", "127.0.0.1:5514", "-syslog-format", "cef", "-syslog-network", "tcp",
		"-export-file", filepath.Join(dir, "rh.ndjson"),
		"-hec-url", "https://splunk.example:8088", "-hec-token-file", tok,
	).build(hfs.Meta{Product: "rulehawk"})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(chs); got != "webhook-v2,syslog-cef,file,splunk-hec" {
		t.Fatalf("channels %s", got)
	}
}

func TestWebhookV1SendsSecret(t *testing.T) {
	sec := filepath.Join(t.TempDir(), "wh.secret")
	os.WriteFile(sec, []byte("s3\n"), 0o600)
	chs, err := parse(t, "-webhook", "http://x/h", "-webhook-secret-file", sec).build(hfs.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	wh, ok := chs[0].(*notify.WebhookChannel)
	if !ok || wh.Secret != "s3" {
		t.Fatalf("v1 webhook must carry the secret: %+v", chs[0])
	}
}

func TestChannelsRejectBadSettings(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"-webhook", "http://x", "-webhook-format", "v3"},
		{"-syslog", "h:1", "-syslog-format", "xml"},
		{"-syslog", "h:1", "-syslog-network", "tls"},
		{"-syslog", "h:1", "-syslog-format", "json", "-syslog-rfc", "1"},
		{"-hec-url", "https://s:8088"},
		{"-hec-url", "ftp://s", "-hec-token-file", filepath.Join(dir, "missing")},
		{"-export-evidence", "all"},
		{"-webhook", "http://x", "-webhook-secret-file", filepath.Join(dir, "missing")},
	} {
		if _, err := parse(t, args...).build(hfs.Meta{}); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
