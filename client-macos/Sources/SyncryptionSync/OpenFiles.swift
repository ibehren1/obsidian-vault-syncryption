import Darwin
import Foundation

/// Which processes have files open, from libproc (like `lsof`). Only this user's processes
/// can be read, which are the ones that edit this user's folders. This process is left out.
public enum OpenFiles {
    /// For each folder in `roots` (absolute paths), a process other than this one with a file
    /// open inside it, or nothing for the folders no process has a file open in.
    public static func holders(under roots: [String]) -> [String: Int32] {
        let prefixes = roots.map { (root: $0, prefix: realPath($0) + "/") }
        guard !prefixes.isEmpty else { return [:] }
        var out: [String: Int32] = [:]
        let me = getpid()
        for pid in allPids() where pid != me {
            for path in openPaths(pid) {
                for p in prefixes where out[p.root] == nil && path.hasPrefix(p.prefix) { out[p.root] = pid }
            }
            if out.count == prefixes.count { break }
        }
        return out
    }

    /// The name of process `pid`, if this user may read it.
    public static func processName(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 256)
        guard proc_name(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
        return String(cString: buf)
    }

    /// `path` with every symlink resolved, as the kernel reports open files (`/private/var/...`).
    static func realPath(_ path: String) -> String {
        guard let r = realpath(path, nil) else { return path }
        defer { free(r) }
        return String(cString: r)
    }

    private static func allPids() -> [Int32] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        // Room for processes started in between.
        var pids = [Int32](repeating: 0, count: Int(count) + 64)
        let n = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        return n > 0 ? Array(pids.prefix(Int(n))) : []
    }

    /// The paths of the files `pid` has open. Empty if it can't be read (another user's).
    private static func openPaths(_ pid: Int32) -> [String] {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return [] }
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / fdSize + 16)
        let got = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        var out: [String] = []
        for fd in fds.prefix(Int(got) / fdSize) where fd.proc_fdtype == PROX_FDTYPE_VNODE {
            var info = vnode_fdinfowithpath()
            let n = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &info, Int32(MemoryLayout<vnode_fdinfowithpath>.size))
            guard n == Int32(MemoryLayout<vnode_fdinfowithpath>.size) else { continue }
            let path = withUnsafeBytes(of: &info.pvip.vip_path) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            if !path.isEmpty { out.append(path) }
        }
        return out
    }
}
