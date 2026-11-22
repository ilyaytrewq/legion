// Package portscan checks TCP port reachability on one or more hosts using
// ordinary TCP connect scanning. It uses only the Go standard library.
//
// # Scanning and cancellation
//
// Construct a [Scanner] with [New]; its zero value cannot scan. A Scanner
// supports concurrent scans and shares its connection limit across them.
// DNS lookups have a separate shared limit of min(32, concurrency).
//
// [Scanner.Scan] streams results in unspecified order. To let the scan finish,
// drain the channel or cancel the context if you stop reading. Scan first
// checks for a nil context or an uninitialized scanner, then returns
// (nil, ctx.Err()) for an already canceled or expired context before validating
// targets or ports. Cancellation observed while parsing targets also prevents
// the scan from starting. Once scanning starts, delivery after cancellation is
// best effort: more results may arrive before closure, and even computed results
// may be dropped. [Scanner.ScanAll] returns the results it collected together
// with ctx.Err() on cancellation. It stores every delivered result, so prefer
// Scan for large scans that do not need to retain all results.
//
// The scan context covers DNS resolution as well as connections. Use a context
// deadline to bound the entire scan; [WithConnectTimeout] only bounds an
// individual TCP connection attempt. Custom [Dialer] and [Resolver]
// implementations must respect context cancellation and support concurrent use.
// A [Result] has a nil Err if and only if its State is [StateOpen]. Each
// resolution-failure result owns its [TargetError] wrapper, but the wrapped
// resolver error can be shared and must be treated as read-only. On Unix and
// Windows, a connection reset is [StateError], not [StateClosed].
//
// # Targets and ports
//
// Targets can be IPv4 or IPv6 literals (including IPv6 scope zones), ASCII DNS
// names, or CIDR prefixes. DNS labels accept ASCII letters, digits, underscores
// and hyphens, but cannot start or end with a hyphen. A single trailing dot is
// allowed. An input of only digits and dots that is not a valid IP address is
// rejected rather than passed to DNS. Target strings are deduplicated exactly;
// different spellings that identify the same address are scanned separately.
//
// CIDR prefixes are masked and expanded inclusively, with at most 65,536
// addresses per prefix before filtering. Explicit unspecified addresses and
// prefixes consisting of a single unspecified address are invalid. Larger
// prefixes and DNS responses skip unspecified addresses. If DNS returns no
// usable addresses, each requested port gets a [StateUnresolved] result unless
// delivery is interrupted. [WithFirstAddrOnly] takes the first usable DNS address.
// CIDR validation errors can be recognized with errors.As and [TargetError].
//
// A nonempty [PortSet] round-trips through [PortSet.String] and [ParsePorts].
// ParsePorts returns [ErrNoPorts] for blank input, wraps [ErrInvalidPort] for
// malformed or out-of-range ports, and wraps [ErrInvalidPortRange] for reversed
// ranges with valid endpoints.
//
// For usage and development instructions, see the [README].
//
// [README]: https://github.com/ilyaytrewq/postscan#readme
package portscan
