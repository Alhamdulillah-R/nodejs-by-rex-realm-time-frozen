#ifndef SRC_REXMIRROR_RELEASE_H_
#define SRC_REXMIRROR_RELEASE_H_

// The RexMirror release record.  A release is named by a song lyric, not a
// number: `node --version` prints the lyric, and RexMirror.info exposes the
// same record to JS through the realm-time binding, so the two cannot drift.
// process.version keeps upstream's v26.7.0 so semver tooling is untouched.
//
// Shipping a build: bump the four values below, append the matching entry
// (with its change list) to `releases` in lib/internal/bootstrap/node.js,
// rebuild both hosts, tag release/<serial>-<slug>.  Bootstrap refuses to
// start when the two records disagree.
// Strings are UTF-8; non-ASCII bytes are written as escapes so the result does
// not depend on the compiler's source charset (\xc3\xb9 is "u with grave").
#define REXMIRROR_RELEASE_SERIAL 4
#define REXMIRROR_RELEASE_LYRIC \
  "I can't afford a carriage, But you'll look sweet upon the seat"
#define REXMIRROR_RELEASE_SONG "Daisy Bell"
#define REXMIRROR_RELEASE_DATE "2026-11-25"

#endif  // SRC_REXMIRROR_RELEASE_H_
