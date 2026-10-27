/// The client's own version (x.y.z, independent of the plugin and the backend). Kept equal to
/// `MARKETING_VERSION` in project.yml; a test checks that.
public let clientVersion = "0.1.37"

/// The protocol version this client speaks (docs/protocol.md 13), sent as
/// `X-Syncryption-Protocol`. Raised only for a breaking API change, on both sides.
public let protocolVersion = 1
