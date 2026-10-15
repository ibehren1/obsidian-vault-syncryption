import CoreServices
import Foundation

/// Reports changed files in a folder through FSEvents, as folder-relative paths. Events are
/// hints: the engine's scan finds anything they miss.
public final class FolderWatcher: @unchecked Sendable {
    private var stream: FSEventStreamRef?
    private let root: String
    private let queue = DispatchQueue(label: "syncryption.folder-watcher")
    private let onChange: @Sendable ([String]) -> Void

    /// `onChange` gets the changed paths, on a background queue, at most every `latency` seconds.
    public init(root: URL, latency: TimeInterval = 0.5, onChange: @escaping @Sendable ([String]) -> Void) {
        self.root = root.standardizedFileURL.resolvingSymlinksInPath().path
        self.onChange = onChange
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil,
                                           copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, paths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FolderWatcher>.fromOpaque(info).takeUnretainedValue()
            let list = Unmanaged<CFArray>.fromOpaque(paths).takeUnretainedValue() as! [String]
            watcher.deliver(Array(list.prefix(count)))
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagNoDefer)
        stream = FSEventStreamCreate(nil, callback, &context, [self.root] as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                     latency, flags)
        if let stream {
            FSEventStreamSetDispatchQueue(stream, queue)
            FSEventStreamStart(stream)
        }
    }

    private func deliver(_ paths: [String]) {
        let prefix = root.hasSuffix("/") ? root : root + "/"
        let rel = paths.compactMap { p -> String? in
            let resolved = p.hasPrefix("/private/") && !prefix.hasPrefix("/private/") ? String(p.dropFirst(8)) : p
            return resolved.hasPrefix(prefix) ? String(resolved.dropFirst(prefix.count)) : nil
        }
        if !rel.isEmpty { onChange(rel) }
    }

    public func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    deinit { stop() }
}
