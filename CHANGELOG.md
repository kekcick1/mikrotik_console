# Changelog

## 2026-04-05 (Stable UX Update)

### Added
- Live bulk-backup progress list in Device Backups (immediate PENDING rows, then OK/FAIL updates per device).
- Bulk result filter controls: All, OK, FAIL.

### Changed
- Bulk backup output is now structured and readable instead of a single long status line.

## 2026-04-04 (Update 2)

### Added
- Backups page action `Backup All Reachable`.
- Sequential per-device backup flow using the same endpoint as manual device backup.
- Progress and summary output for bulk backup (OK/FAILED/TOTAL).

### Changed
- Bulk backup runs in order (one device at a time) to avoid SSH overload.

## 2026-04-04

### Added
- Standalone and Traefik compose files for easy start.
- Global device selector in navbar.
- Toast notifications stack.
- Terminal command history with ArrowUp/ArrowDown.
- Device search/filter and device edit action in Devices page.
- Interface table columns: Port and Comment.
- Full system backup actions in Backups page (create/list/download/restore).

### Changed
- Dashboard no longer triggers unintended auto-connect on device card selection.
- Dashboard auto refresh updates only cards for manually connected devices.
- Router logs are shown in natural order (old at top, new at bottom).
- Static script URLs use cache-busting query version.

### Fixed
- Documentation aligned with current run modes and release behavior.
