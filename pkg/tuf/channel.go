package tuf

import "fmt"

// Channels are the release lanes. A release is published into
// "develop"; promotion copies the *same* target (identical hash) into
// "testing" and then "stable". There is no ordering authority beyond
// the version string — promotion is proven by the artefact hash being
// present in the senior channel, signed by that channel's key.
const (
	ChannelDevelop = "develop"
	ChannelTesting = "testing"
	ChannelStable  = "stable"
)

// ChannelOrder lists channels from junior to senior.
var ChannelOrder = []string{ChannelDevelop, ChannelTesting, ChannelStable}

// IsChannel reports whether name is a known release channel.
func IsChannel(name string) bool {
	for _, c := range ChannelOrder {
		if c == name {
			return true
		}
	}
	return false
}

// PromotedTo reports the most senior channel whose metadata pins a
// target with the same sha256 hash (and path) as the one found in
// fromChannel. It is the cross-check the update service runs before
// offering an update: an artefact is "in stable" only when the stable
// role itself signed a target with that exact hash.
func (c *Chain) PromotedTo(fromChannel, path string) (string, bool) {
	src, ok := c.Target(fromChannel, path)
	if !ok {
		return "", false
	}
	srcHash, ok := src.Hashes[hashAlgoSHA256]
	if !ok {
		return "", false
	}
	best := ""
	for _, ch := range ChannelOrder {
		if ch == fromChannel {
			continue
		}
		t, ok := c.Channels[ChannelRolePrefix+ch]
		if !ok {
			continue
		}
		tg, ok := t.Targets[path]
		if !ok {
			continue
		}
		if h, ok := tg.Hashes[hashAlgoSHA256]; ok && h == srcHash {
			best = ch
		}
	}
	return best, best != ""
}

// PromoteTarget builds the delegated-role metadata for channel adding
// (or replacing, by path) target. The producer signs the result with
// the channel key and pins it in snapshot; version must increase
// monotonically per channel.
func PromoteTarget(t *Targets, channel, path string, target Target) *Targets {
	out := *t
	out.Version = t.Version + 1
	out.Targets = make(map[string]Target, len(t.Targets)+1)
	for k, v := range t.Targets {
		out.Targets[k] = v
	}
	out.Targets[path] = target
	return &out
}

// CheckPromotion verifies that channel's copy of path is byte-identical
// (same pinned sha256) with the copy in fromChannel.
func CheckPromotion(chain *Chain, fromChannel, toChannel, path string) error {
	if !IsChannel(fromChannel) || !IsChannel(toChannel) {
		return fmt.Errorf("tuf: unknown channel in promotion %q → %q", fromChannel, toChannel)
	}
	src, ok := chain.Target(fromChannel, path)
	if !ok {
		return fmt.Errorf("tuf: promotion source %s:%s not found", fromChannel, path)
	}
	dst, ok := chain.Target(toChannel, path)
	if !ok {
		return fmt.Errorf("tuf: promotion target %s:%s not promoted yet", toChannel, path)
	}
	srcHash, ok := src.Hashes[hashAlgoSHA256]
	if !ok {
		return fmt.Errorf("tuf: %s:%s has no sha256 pin", fromChannel, path)
	}
	dstHash, ok := dst.Hashes[hashAlgoSHA256]
	if !ok {
		return fmt.Errorf("tuf: %s:%s has no sha256 pin", toChannel, path)
	}
	if srcHash != dstHash {
		return fmt.Errorf("tuf: promotion mismatch: %s:%s is %s, %s:%s is %s",
			fromChannel, path, srcHash, toChannel, path, dstHash)
	}
	return nil
}
