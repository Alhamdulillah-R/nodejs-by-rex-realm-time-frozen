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
#define REXMIRROR_RELEASE_SERIAL 1
#define REXMIRROR_RELEASE_LYRIC "she Medusa with a little Pocahontas"
#define REXMIRROR_RELEASE_SONG "Wasted"
#define REXMIRROR_RELEASE_DATE "2026-09-04"

#endif  // SRC_REXMIRROR_RELEASE_H_
