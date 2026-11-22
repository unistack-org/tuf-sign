package main

import (
	"fmt"
	"strings"
	"time"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// resignRefreshWindow: snapshot is refreshed when it (or any role it
// pins) expires within this window.
const resignRefreshWindow = 72 * time.Hour

// runResign re-signs the timestamp role (always) and refreshes the
// snapshot when it — or any role file it pins — is close to expiry.
// This is the 12h cron for a CDN tree with no releases.
func runResign(args []string) error {
	f, err := parseFlags(args, map[string]string{
		"state": "", "key-snapshot": "", "key-timestamp": "",
		"snapshot-expires": "", "timestamp-expires": "",
	}, nil)
	if err != nil {
		return err
	}
	st := state{dir: f.get("state")}
	if st.dir == "" {
		return fmt.Errorf("flag -state is required")
	}
	snapPriv, err := loadKey(f.get("key-snapshot"))
	if err != nil {
		return err
	}
	tsPriv, err := loadKey(f.get("key-timestamp"))
	if err != nil {
		return err
	}
	now := nowUTC()

	needSnapshot := false
	snapEnv, err := st.loadSigned(tuf.SnapshotRole)
	if err != nil {
		return err
	}
	snap, err := tuf.Decode(snapEnv, tuf.SnapshotRole)
	if err != nil {
		return err
	}
	sm := snap.(*tuf.Snapshot)
	if time.Until(sm.MetaExpires()) < resignRefreshWindow {
		needSnapshot = true
	}
	for _, role := range st.metaRoles() {
		env, err := st.loadSigned(role)
		if err != nil {
			return err
		}
		m, err := tuf.Decode(env, roleTypeOf(role))
		if err != nil {
			return err
		}
		if time.Until(m.MetaExpires()) < resignRefreshWindow {
			needSnapshot = true
		}
	}
	if needSnapshot {
		if err := st.refresh(snapPriv, tsPriv, now,
			duration(f.get("snapshot-expires"), defaultSnapshotExpiry),
			duration(f.get("timestamp-expires"), defaultTimestampExpiry)); err != nil {
			return err
		}
		fmt.Println("resign: snapshot refreshed, timestamp re-signed")
		return nil
	}

	// Timestamp-only refresh.
	env, err := st.loadSigned(tuf.TimestampRole)
	if err != nil {
		return err
	}
	tm, err := tuf.Decode(env, tuf.TimestampRole)
	if err != nil {
		return err
	}
	ts := tm.(*tuf.Timestamp)
	ts.Version++
	ts.Expires = now.Add(duration(f.get("timestamp-expires"), defaultTimestampExpiry))
	tsEnv, err := tuf.SignCanonical(ts, tsPriv)
	if err != nil {
		return err
	}
	if err := st.writeSigned(tuf.TimestampRole, tsEnv); err != nil {
		return err
	}
	fmt.Println("resign: timestamp re-signed (snapshot still fresh)")
	return nil
}

// roleTypeOf maps a role *name* ("channel/develop") to its metadata
// "type" field value ("targets" for channel roles).
func roleTypeOf(role string) string {
	if strings.HasPrefix(role, tuf.ChannelRolePrefix) {
		return tuf.TargetsRole
	}
	return role
}
