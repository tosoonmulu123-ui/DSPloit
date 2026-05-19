//
//  ReleaseUI.swift
//  DSPloit — shared release-ready UI components
//

import SwiftUI

// MARK: - Readiness

enum DSPRequirement: String, CaseIterable {
    case kernel = "Kernel exploit"
    case vfs = "VFS access"
    case sandbox = "Sandbox escape"
    case remoteCall = "RemoteCall"

    func isMet(by mgr: dspmgr) -> Bool {
        switch self {
        case .kernel: return mgr.dsready
        case .vfs: return mgr.vfsready
        case .sandbox: return mgr.sbxready
        case .remoteCall: return mgr.rcready
        }
    }

    var icon: String {
        switch self {
        case .kernel: return "cpu"
        case .vfs: return "doc.on.doc"
        case .sandbox: return "lock.open"
        case .remoteCall: return "antenna.radiowaves.left.and.right"
        }
    }
}

enum FeatureBadge: String {
    case ready = "Ready"
    case locked = "Locked"
    case beta = "Beta"
    case advanced = "Advanced"

    var color: Color {
        switch self {
        case .ready: return .green
        case .locked: return .secondary
        case .beta: return .orange
        case .advanced: return .purple
        }
    }
}

// MARK: - Readiness banner

struct ReadinessBanner: View {
    @ObservedObject var mgr: dspmgr
    let requirement: DSPRequirement
    var hint: String?

    private var met: Bool { requirement.isMet(by: mgr) }

    var body: some View {
        if !met {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Butuh: \(requirement.rawValue)")
                        .font(.subheadline.bold())
                    Text(hint ?? defaultHint)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.orange.opacity(0.12))
            )
            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
            .listRowBackground(Color.clear)
        }
    }

    private var defaultHint: String {
        switch requirement {
        case .kernel:
            return "Buka tab Main → tap Jailbreak untuk menjalankan exploit kernel."
        case .vfs:
            return "Selesaikan jailbreak di Main. VFS aktif setelah System Init."
        case .sandbox:
            return "Selesaikan jailbreak di Main. Sandbox escape aktif setelah System Init."
        case .remoteCall:
            return "Selesaikan jailbreak di Main sampai langkah RemoteCall hijau."
        }
    }
}

// MARK: - System status strip

struct SystemStatusStrip: View {
    @ObservedObject var mgr: dspmgr
    @ObservedObject var jb: JailbreakEngine = .shared
    @ObservedObject var root: RootExecutor = .shared

    var body: some View {
        HStack(spacing: 6) {
            statusChip("Kernel", on: mgr.dsready)
            statusChip("VFS", on: mgr.vfsready)
            statusChip("SBX", on: mgr.sbxready)
            statusChip("RC", on: mgr.rcready)
            statusChip("Root", on: root.rootConfirmed || jb.isJailbroken)
        }
        .frame(maxWidth: .infinity)
    }

    private func statusChip(_ label: String, on: Bool) -> some View {
        Text(label)
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .background(Capsule().fill(on ? Color.green.opacity(0.2) : Color.secondary.opacity(0.15)))
            .foregroundStyle(on ? Color.green : Color.secondary)
    }
}

// MARK: - Feature row (Tweaks list)

struct FeatureLinkRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    var badge: FeatureBadge = .ready
    var disabled: Bool = false

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(color.opacity(0.14))
                    .frame(width: 40, height: 40)
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(color)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(disabled ? .secondary : .primary)
                    Text(badge.rawValue)
                        .font(.system(size: 9, weight: .bold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(badge.color.opacity(0.2)))
                        .foregroundStyle(badge.color)
                }
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
        .opacity(disabled ? 0.55 : 1)
    }
}

// MARK: - Empty state

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    var buttonTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
            if let buttonTitle, let action {
                Button(buttonTitle, action: action)
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
    }
}

// MARK: - Tool card (Root grid)

struct ToolCard: View {
    let icon: String
    let title: String
    var subtitle: String?
    let color: Color
    var badge: FeatureBadge?

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 22))
                .foregroundStyle(color)
            Text(title)
                .font(.caption.bold())
                .foregroundStyle(.primary)
                .lineLimit(1)
            if let subtitle {
                Text(subtitle)
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
            }
            if let badge {
                Text(badge.rawValue)
                    .font(.system(size: 8, weight: .bold))
                    .foregroundStyle(badge.color)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .padding(.horizontal, 6)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }
}

// MARK: - Tool row (list style, kept for compatibility)

struct ToolRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(color.opacity(0.12))
                    .frame(width: 40, height: 40)
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(color)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.bold())
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
