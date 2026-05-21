//
//  LogsView.swift
//  DSPloit
//

import SwiftUI

struct LogsView: View {
    @ObservedObject var logger: Logger
    @State private var search = ""
    @State private var tagFilter: LogTagFilter = .all
    @State private var followTail = true

    private let nobullshitkey = "loggernobullshit"
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
                filterBar

                if UserDefaults.standard.bool(forKey: nobullshitkey) {
                    plainList
                } else {
                    styledList
                }
            }
            .navigationTitle("Logs")
            .searchable(text: $search, prompt: "Search logs...")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Toggle(isOn: $followTail) {
                        Image(systemName: "arrow.down.to.line")
                    }
                    .toggleStyle(.button)
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    ShareLink(item: logsURL) {
                        Image(systemName: "square.and.arrow.up")
                    }

                    Button {
                        UIPasteboard.general.string = logger.logs.joined(separator: "\n")
                        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }

                    Button {
                        globallogger.clear()
                    } label: {
                        Image(systemName: "trash")
                    }
                    .foregroundColor(.red)
                }
            }
        }
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(LogTagFilter.allCases) { f in
                    Button {
                        tagFilter = f
                    } label: {
                        Text(f.rawValue)
                            .font(.caption.bold())
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(tagFilter == f ? Color.accentColor : Color.secondary.opacity(0.15))
                            .foregroundStyle(tagFilter == f ? Color.white : .primary)
                            .clipShape(Capsule())
                    }
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .background(Color(.secondarySystemBackground))
    }

    private var styledList: some View {
        ScrollViewReader { proxy in
            List {
                if filtered.isEmpty {
                    LogsEmptyStateView()
                        .listRowBackground(Color.clear)
                } else {
                    ForEach(filtered) { line in
                        LogLineRow(line: line)
                            .listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 0, leading: 12, bottom: 0, trailing: 12))
                            .id(line.id)
                            .onTapGesture {
                                UIPasteboard.general.string = line.raw
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                            }
                    }
                }
            }
            .listStyle(.plain)
            .onChange(of: logger.logs.count) { _ in scrollToEnd(proxy) }
            .onChange(of: followTail) { on in if on { scrollToEnd(proxy) } }
            .onAppear { scrollToEnd(proxy) }
        }
    }

    private var plainList: some View {
        List {
            ForEach(Array(logger.logs.enumerated()), id: \.offset) { _, log in
                Text(log)
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
    }

    private func scrollToEnd(_ proxy: ScrollViewProxy) {
        guard followTail, let last = filtered.last else { return }
        withAnimation(.easeOut(duration: 0.2)) {
            proxy.scrollTo(last.id, anchor: .bottom)
        }
    }
}
