# vendor/i-slint-core-1.18.1

Slint's `i-slint-core` 1.18.1, unchanged except for one bug fix, used through `[patch.crates-io]`
in Cargo.toml. Remove it (and the patch entry) once Slint ships the fix upstream.

## The bug

A Text that is not drawn for two frames can lose its repaints for good. The software renderer
shapes text through a per-item text layout cache whose entries carry their own dependency
tracker; the item's partial-rendering tracker depends on the text only *through* that entry.
When the cache sweeps (after more than 1024 misses, which a window with changing rows reaches
within seconds), it drops the entries not used in the last two frames, trackers included, and
nothing tells the item. From then on its text changes mark nothing dirty: the status line stays
on "round 4" while the property says "round 75" (seen live in VibeTrace, 2026-10-19).

## The fix (two hunks, marked "VibeWare patch")

- `properties.rs`: `PropertyTracker::mark_dependents_dirty()`, crate-private.
- `item_rendering.rs`: `ItemCache::retain` and `ItemCache::release` mark the dependents of every
  tracker they drop dirty, so the item is drawn once more and registers on a fresh entry.

`tests/repaint.rs` reproduces it headless (the real software renderer with a reused buffer) and
fails without the patch. Upstream (slint-ui/slint master, read 2026-10-20) still has the bug.
An upstream issue is drafted, not filed yet.
