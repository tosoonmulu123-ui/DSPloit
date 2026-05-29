//
//  LogsView.swift
//  DSPloit — Terminal-style log viewer
//

import SwiftUI

struct LogsView: View {
    @ObservedObject var logger: Logger
    @State private var search = ""
    @State private var tagFilter: LogTagFilter = .all
    @State private var followTail = true
    @State private var showFilters = false

    let logsURL: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("dsploit.log")
    }()

    private var parsed: [ParsedLogLine] {
        LogLineParser.parse(blocks: logger.logs)
    }

    private var filtered: [ParsedLogLine] {
        parsed.filter { line in
            guard tagFilter.matches(line) else { return false }
            if search.isEmpty { return true }
            return line.raw.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filter chips (collapsible)
                if showFilters { filterBar }
                
                // Terminal-style log area
                logContent
                
                // Bottom bar with stats
                bottomBar
            }
            .background(Color.black)
            .navigationTitle("Console")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    HStack(spacing: 12) {
                        Button {
                            showFilters.toggle()
                        } label: {
                            Image(systemName: "line.3.horizontal.decrease")
                                .foregroundStyle(showFilters ? .blue : .secondary)
                        }
                        Button {
                            followTail.toggle()
                        } label: {
                            Image(systemName: followTail ? "arrow.down.to.line.compact" : "arrow.down.to.line")
                                .foregroundStyle(followTail ? .green : .secondary)
                        }
                    }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {
                        UIPasteboard.general.string = filtered.map(\.raw).joined(separator: "\n")
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.secondary)
                    }
                    ShareLink(item: logsURL) {
                        Image(systemName: "square.and.arrow.up")
                            .foregroundStyle(.secondary)
                    }
                    Button {
                        globallogger.clear()
                    } label: {
                        Image(systemName: "trash")
                            .foregroundStyle(.red.opacity(0.8))
                    }
                }
            }
            .toolbarBackground(Color.black, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .searchable(text: $search, prompt: "Filter...")
        }
        .preferredColorScheme(.dark)
    }
    
    // MARK: - Log Content (Terminal Style)
    
    private var logContent: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(filtered) { line in
                        terminalLine(line)
                            .id(line.id)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
            }
            .background(Color.black)
            .onChange(of: logger.logs.count) { _ in scrollToEnd(proxy) }
            .onChange(of: followTail) { on in if on { scrollToEnd(proxy) } }
            .onAppear { scrollToEnd(proxy) }
        }
    }
    
    private func terminalLine(_ line: ParsedLogLine) -> some View {
        Group {
            if line.isDivider {
                Rectangle()
                    .fill(Color.gray.opacity(0.3))
                    .frame(height: 1)
                    .padding(.vertical, 4)
            } else if line.isSessionStart {
                HStack(spacing: 6) {
                    Text("▶")
                        .foregroundStyle(.cyan)
                    Text(line.body)
                        .foregroundStyle(.cyan)
                        .bold()
                }
                .font(.system(size: 11, design: .monospaced))
                .padding(.vertical, 4)
            } else {
                HStack(alignment: .top, spacing: 0) {
                    // Colored dot
                    Text("●")
                        .font(.system(size: 6))
                        .foregroundStyle(line.level.color)
                        .frame(width: 12)
                        .padding(.top, 4)
                    
                    // Tag (dim)
                    if let tag = line.tag {
                        Text("[\(tag)]")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.gray)
                            .padding(.trailing, 4)
                    }
                    
                    // Body
                    Text(line.body)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(lineColor(line))
                        .textSelection(.enabled)
                }
                .padding(.vertical, 1)
            }
        }
    }
    
    private func lineColor(_ line: ParsedLogLine) -> Color {
        switch line.level {
        case .success: return .green
        case .error: return .red
        case .warning: return .yellow
        case .info: return Color(.init(white: 0.85, alpha: 1))
        }
    }
    
    // MARK: - Filter Bar
    
    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(LogTagFilter.allCases) { f in
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { tagFilter = f }
                    } label: {
                        Text(f.rawValue)
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(tagFilter == f ? Color.blue : Color.white.opacity(0.08))
                            .foregroundStyle(tagFilter == f ? .white : .gray)
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
        }
        .background(Color.black)
    }
    
    // MARK: - Bottom Bar
    
    private var bottomBar: some View {
        HStack {
            Text("\(filtered.count) lines")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.gray)
            
            Spacer()
            
            if tagFilter != .all {
                Text("filter: \(tagFilter.rawValue)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.blue)
            }
            
            Spacer()
            
            Circle()
                .fill(followTail ? .green : .gray)
                .frame(width: 6, height: 6)
            Text(followTail ? "LIVE" : "PAUSED")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundStyle(followTail ? .green : .gray)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Color(.init(white: 0.08, alpha: 1)))
    }
    
    // MARK: - Helpers
    
    private func scrollToEnd(_ proxy: ScrollViewProxy) {
        guard followTail, let last = filtered.last else { return }
        withAnimation(.easeOut(duration: 0.15)) {
            proxy.scrollTo(last.id, anchor: .bottom)
        }
    }
}
