import AppKit
import SwiftUI
import SyncryptionAppCore

/// Shared building blocks, so every window reads the same way.

extension FolderController.Kind {
    var color: Color {
        switch self {
        case .ok: .green
        case .busy: .accentColor
        case .warn: .orange
        case .error: .red
        case .off: .secondary
        }
    }
}

struct StatusDot: View {
    let kind: FolderController.Kind
    var size: CGFloat = 8

    var body: some View {
        Circle().fill(kind.color).frame(width: size, height: size)
    }
}

/// The state as a coloured capsule.
struct StatePill: View {
    let text: String
    let kind: FolderController.Kind

    var body: some View {
        HStack(spacing: 5) {
            StatusDot(kind: kind, size: 6)
            Text(text).font(.caption.weight(.semibold))
        }
        .foregroundStyle(kind == .off ? Color.secondary : kind.color)
        .padding(.horizontal, 9)
        .padding(.vertical, 3)
        .background(Capsule().fill(kind.color.opacity(0.13)))
    }
}

struct Logo: View {
    var size: CGFloat = 40

    var body: some View {
        Image("Logo").resizable().interpolation(.high).frame(width: size, height: size)
            .shadow(color: .black.opacity(0.15), radius: 1, y: 0.5)
    }
}

/// A figure with its label and a detail line.
struct Tile: View {
    let label: String
    let value: String
    let detail: String
    var systemImage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 5) {
                if let systemImage { Image(systemName: systemImage).foregroundStyle(.secondary) }
                Text(label).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            }
            Text(value).font(.system(size: 22, weight: .semibold)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.6)
            Text(detail.isEmpty ? " " : detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(14)
        .background(CardBackground())
    }
}

struct CardBackground: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 10, style: .continuous)
            .fill(Color(nsColor: .controlBackgroundColor))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color(nsColor: .separatorColor).opacity(0.6)))
    }
}

/// A titled section with an optional count and accessory.
struct Card<Content: View, Accessory: View>: View {
    let title: String
    var count: String?
    @ViewBuilder var accessory: () -> Accessory
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(.headline)
                if let count { Text(count).font(.subheadline).foregroundStyle(.secondary).monospacedDigit() }
                Spacer()
                accessory()
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(16)
        .background(CardBackground())
    }
}

extension Card where Accessory == EmptyView {
    init(title: String, count: String? = nil, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.count = count
        accessory = { EmptyView() }
        self.content = content
    }
}

/// A label and its value, in a two-column grid.
struct KeyValue<Value: View>: View {
    let label: String
    @ViewBuilder var value: () -> Value

    var body: some View {
        GridRow(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            value().frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// `SHA256:AbCd…WxYz`, the whole fingerprint on hover and in the context menu.
struct Fingerprint: View {
    let value: String

    var short: String {
        let body = value.hasPrefix("SHA256:") ? String(value.dropFirst(7)) : value
        guard body.count > 14 else { return value }
        return "SHA256:\(body.prefix(6))…\(body.suffix(6))"
    }

    var body: some View {
        Text(short).font(.callout.monospaced()).foregroundStyle(.secondary).help(value)
            .contextMenu { Button("Copy Fingerprint") { copy(value) } }
    }
}

/// A small tag after a name.
struct Tag: View {
    let text: String
    var color: Color = .secondary

    var body: some View {
        Text(text).font(.caption2.weight(.semibold)).foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 1.5)
            .background(Capsule().strokeBorder(color.opacity(0.5)))
    }
}

func copy(_ s: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(s, forType: .string)
}

/// "2 minutes ago", or "just now" (`capitalized` for the start of a line).
func relative(_ date: Date, to now: Date = Date(), capitalized: Bool = false) -> String {
    if now.timeIntervalSince(date) < 10 { return capitalized ? "Just now" : "just now" }
    let f = RelativeDateTimeFormatter()
    f.unitsStyle = .full
    return f.localizedString(for: date, relativeTo: now)
}

func isoDate(_ iso: String?) -> Date? {
    guard let iso else { return nil }
    let f = ISO8601DateFormatter()
    if let d = f.date(from: iso) { return d }
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: iso)
}

func host(_ endpoint: String) -> String { URL(string: endpoint)?.host() ?? endpoint }

func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String {
    "\(n.formatted()) \(n == 1 ? one : many ?? one + "s")"
}

/// A row that highlights like a native menu item.
struct MenuRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { Row(configuration: configuration) }

    struct Row: View {
        let configuration: Configuration
        @State private var hover = false
        @Environment(\.isEnabled) private var enabled

        var body: some View {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .foregroundStyle(textColor)
                .background(RoundedRectangle(cornerRadius: 5, style: .continuous).fill(fill))
                .contentShape(Rectangle())
                .onHover { hover = $0 }
        }

        private var textColor: Color {
            if !enabled { return .secondary }
            return hover ? .white : .primary
        }

        private var fill: Color { hover && enabled ? .accentColor : .clear }
    }
}
