//
//  LogFormatting.swift
//  DSPloit — parsed, color-coded log lines for LogsView
//

import SwiftUI

enum LogLineLevel: String {
    case success
    case error
    case warning
    case info

    var color: Color {
        switch self {
        case .success: return .green
        case .error: return .red
        case .warning: return .orange
        case .info: return .primary
        }
    }

    var icon: String? {
        switch self {
        case .success: return "checkmark.circle.fill"
        case .error: return "xmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info: return nil
        }
    }
}

struct ParsedLogLine: Identifiable {
    let id: Int
    let raw: String
    let tag: String?
    let body: String
    let level: LogLineLevel
    let isDivider: Bool
    let isSessionStart: Bool
}

enum LogTagFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case jb = "Chain"
    case amfi = "AMFI"
    case ds = "Exploit"
    case pmap = "pmap_cs"
    case tc = "TrustCache"
    case vfs = "VFS"
    case sbx = "Sandbox"
    case rc = "RC"
    case root = "Root"
    case offs = "Offsets"

    var id: String { rawValue }

    func matches(_ line: ParsedLogLine) -> Bool {
        if self == .all { return true }
        guard let tag = line.tag?.lowercased() else {
            // Also match lines without explicit tags by content
            let lower = line.raw.lowercased()
            switch self {
            case .amfi: return lower.contains("amfi") || lower.contains("cs_flag") || lower.contains("enforcement")
            case .pmap: return lower.contains("pmap") || lower.contains("trust_level") || lower.contains("allow_invalid")
            case .tc: return lower.contains("trust cache") || lower.contains("trust_cache") || lower.contains("cdhash") || lower.contains("msm")
            case .jb: return lower.contains("jailbreak") || lower.contains("step ")
            default: return false
            }
        }
        switch self {
        case .all: return true
        case .jb: return tag == "jb"
        case .amfi: return tag == "amfi" || tag == "exp_amfid" || tag == "exp_flagscan"
        case .ds: return tag == "ds" || tag == "pe"
        case .pmap: return tag.contains("pmap")
        case .tc: return tag == "tc" || tag == "tc79" || tag.contains("trust")
        case .vfs: return tag == "vfs"
        case .sbx: return tag == "sbx"
        case .rc: return tag == "rc"
        case .root: return tag == "root"
        case .offs: return tag == "offs" || tag.contains("kcache") || tag.contains("offsets")
        }
    }
}

enum LogLineParser {
    static func parse(blocks: [String]) -> [ParsedLogLine] {
        var out: [ParsedLogLine] = []
        var id = 0
        for block in blocks {
            let lines = block.components(separatedBy: "\n")
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty { continue }
                out.append(parseOne(trimmed, id: id))
                id += 1
            }
        }
        return out
    }

    private static func parseOne(_ line: String, id: Int) -> ParsedLogLine {
        if line.hasPrefix("DSPloit started:") {
            return ParsedLogLine(id: id, raw: line, tag: nil, body: line, level: .info, isDivider: false, isSessionStart: true)
        }
        if isDividerLine(line) {
            return ParsedLogLine(id: id, raw: line, tag: nil, body: "", level: .info, isDivider: true, isSessionStart: false)
        }

        var tag: String?
        var body = line
        if let open = line.firstIndex(of: "("),
           let close = line[line.index(after: open)...].firstIndex(of: ")") {
            let inner = line[line.index(after: open)..<close]
            if !inner.contains(" ") && inner.count < 24 {
                tag = String(inner)
                body = String(line[line.index(after: close)...]).trimmingCharacters(in: .whitespaces)
            }
        }

        return ParsedLogLine(
            id: id,
            raw: line,
            tag: tag,
            body: body.isEmpty ? line : body,
            level: level(for: line),
            isDivider: false,
            isSessionStart: false
        )
    }

    private static let dividerChars: Set<Character> = ["-", "=", "_", "*", "#"]

    private static func isDividerLine(_ line: String) -> Bool {
        let t = line.trimmingCharacters(in: .whitespaces)
        guard t.count >= 3 else { return false }
        return Set(t).isSubset(of: dividerChars)
    }

    private static func level(for line: String) -> LogLineLevel {
        let lower = line.lowercased()
        if line.contains("✅") || lower.contains("success") || lower.contains(" escaped!")
            || lower.contains(" ready!") || lower.contains(" resolve ok")
            || lower.contains("jailbreak complete") || lower.contains("exploit success")
            || lower.contains("patched!") || lower.contains("amfi bypassed")
            || lower.contains("unsigned code allowed") || lower.contains("trust_cache_load_gate enabled")
            || line.contains("🎉") {
            return .success
        }
        if line.contains("❌") || lower.contains("failed") || lower.contains("error:")
            || lower.contains("xpf start error") || lower.contains("panic")
            || lower.contains("ppl blocked") || lower.contains("write failed") {
            return .error
        }
        if line.contains("⚠️") || lower.contains("warn") || lower.contains("continuing")
            || lower.contains("skip") || lower.contains("fallback")
            || lower.contains("incomplete") || lower.contains("hardcoded") {
            return .warning
        }
        return .info
    }
}

struct LogLineRow: View {
    let line: ParsedLogLine

    var body: some View {
        if line.isDivider {
            Divider().padding(.vertical, 6)
        } else if line.isSessionStart {
            HStack {
                Image(systemName: "play.circle.fill")
                    .foregroundStyle(.blue)
                Text(line.body)
                    .font(.subheadline.bold())
            }
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.blue.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        } else {
            HStack(alignment: .top, spacing: 8) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(line.level.color)
                    .frame(width: 3)

                VStack(alignment: .leading, spacing: 4) {
                    if let tag = line.tag {
                        Text(tag)
                            .font(.caption2.bold())
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.15))
                            .clipShape(Capsule())
                    }
                    HStack(alignment: .top, spacing: 6) {
                        if let icon = line.level.icon {
                            Image(systemName: icon)
                                .font(.caption)
                                .foregroundStyle(line.level.color)
                                .padding(.top, 2)
                        }
                        Text(line.body)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(line.level == .info ? .primary : line.level.color)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }
}

struct LogsEmptyStateView: View {
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "line.3.horizontal.decrease.circle")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("No lines")
                .font(.headline)
            Text("Change filter or run Jailbreak / AMFI again.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 36)
    }
}
