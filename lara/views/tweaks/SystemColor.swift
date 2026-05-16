import SwiftUI
import Foundation

struct carcolorentry {
    let name: String
    let coloroff: Int

    let ogb: UInt8
    let ogg: UInt8
    let ogr: UInt8
    let oga: UInt8

    var b: UInt8
    var g: UInt8
    var r: UInt8
    var a: UInt8
}

enum carparser {
    static func tou32be(_ data: Data, _ off: Int) -> UInt32 {
        (UInt32(data[off]) << 24) |
        (UInt32(data[off + 1]) << 16) |
        (UInt32(data[off + 2]) << 8) |
        UInt32(data[off + 3])
    }

    static func tou16be(_ data: Data, _ off: Int) -> UInt16 {
        (UInt16(data[off]) << 8) |
        UInt16(data[off + 1])
    }

    static func parse(_ data: Data) throws -> [carcolorentry] {
        let magic = String(bytes: data[0..<8], encoding: .ascii)
        guard magic == "BOMStore" else {
            throw NSError(domain: "CAR", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid file"])
        }

        let idxoff = Int(tou32be(data, 0x10))
        let varoff = Int(tou32be(data, 0x18))

        let varcount = Int(tou32be(data, varoff))
        var p = varoff + 4

        var blocks: [String: Int] = [:]

        for _ in 0..<varcount {
            let id = Int(tou32be(data, p)); p += 4
            let len = Int(data[p]); p += 1

            let name = String(bytes: data[p..<p+len], encoding: .ascii) ?? ""
            p += len

            blocks[name] = id
        }

        guard let colorsblock = blocks["COLORS"] else {
            throw NSError(domain: "CAR", code: 2)
        }

        let nptr = Int(tou32be(data, idxoff))
        var ptrs: [(Int, Int)] = []

        for i in 0..<nptr {
            let off = Int(tou32be(data, idxoff + 4 + i*8))
            let len = Int(tou32be(data, idxoff + 4 + i*8 + 4))
            ptrs.append((off, len))
        }

        let root = ptrs[colorsblock]

        let treemagic = String(bytes: data[root.0..<root.0+4], encoding: .ascii)
        guard treemagic == "tree" else { throw NSError(domain: "CAR", code: 3) }

        let childid = Int(tou32be(data, root.0 + 8))
        let child = ptrs[childid]

        let isleaf = tou16be(data, child.0)
        let count = Int(tou16be(data, child.0 + 2))

        guard isleaf != 0 else { throw NSError(domain: "CAR", code: 4) }

        var result: [carcolorentry] = []

        for i in 0..<count {
            let eOff = child.0 + 12 + i*8

            let valblk = Int(tou32be(data, eOff))
            let keyblk = Int(tou32be(data, eOff + 4))

            let key = ptrs[keyblk]
            let val = ptrs[valblk]

            var s = key.0
            let end = key.0 + key.1

            while s < end && data[s] == 0 { s += 1 }

            var e = s
            while e < end && data[e] != 0 { e += 1 }

            let name = String(bytes: data[s..<e], encoding: .ascii) ?? "?"

            let cOff = val.0 + 8

            let b = data[cOff]
            let g = data[cOff+1]
            let r = data[cOff+2]
            let a = data[cOff+3]

            result.append(carcolorentry(
                name: name,
                coloroff: cOff,
                ogb: b, ogg: g, ogr: r, oga: a,
                b: b, g: g, r: r, a: a
            ))
        }

        return result.sorted { $0.name < $1.name }
    }
}

struct entry: Identifiable {
    let id = UUID()
    let name: String

    let ogr: UInt8
    let ogg: UInt8
    let ogb: UInt8
    let oga: UInt8

    var r: UInt8
    var g: UInt8
    var b: UInt8
    var a: UInt8

    var edited: Bool {
        r != ogr || g != ogg || b != ogb || a != oga
    }

    var color: Color {
        Color(
            red: Double(r)/255,
            green: Double(g)/255,
            blue: Double(b)/255,
            opacity: Double(a)/255
        )
    }

    var hex: String {
        "#" + String(format: "%02X%02X%02X (%02X)", r, g, b, a)
    }
}

struct SystemColor: View {
    @ObservedObject var mgr: dspmgr
    @State private var entries: [entry] = []
    @State private var status = "Not loaded"
    @State private var ogdata: Data?
    @State private var parsedentries: [carcolorentry] = []
    
    let syspath = "/System/Library/PrivateFrameworks/CoreUI.framework/DesignLibrary-iOS.bundle/iOSRepositories/DarkStandard.car"

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(entries.indices, id: \.self) { i in
                        let e = entries[i]
                        
                        HStack {
                            ColorPicker("", selection: Binding(
                                get: { e.color },
                                set: { newColor in
                                    let ui = UIColor(newColor)
                                    var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
                                    ui.getRed(&r, green: &g, blue: &b, alpha: &a)
                                    
                                    entries[i].r = UInt8(r * 255)
                                    entries[i].g = UInt8(g * 255)
                                    entries[i].b = UInt8(b * 255)
                                    entries[i].a = UInt8(a * 255)
                                }
                            ))
                            .labelsHidden()
                            .frame(width: 40)
                            
                            VStack(alignment: .leading) {
                                Text(e.name)
                                    .font(.caption)
                                    .bold()
                                
                                Text(e.hex)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            
                            Spacer()
                        }
                    }
                } footer: {
                    Text("[Respring](https://roooot.dev/respring.html) to apply. \n")
                    + Text(status)
                }
                
                Section {
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/yupa-tt.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("Yupa")
                                .font(.headline)
                            
                            Text("The original [SystemColors Patcher](https://yupa-tt.github.io/SystemColor/).")
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/yupa-tt"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                } header: {
                    Text("Credits")
                }
            }
            .navigationTitle("SystemColors")
            .toolbar {
                Button {
                    apply()
                } label: {
                    Image(systemName: "checkmark.circle.fill")
                }
            }
            .onAppear(perform: load)
        }
    }

    func load() {
        let path = syspath
        let url = URL(fileURLWithPath: path)

        do {
            let data = try Data(contentsOf: url)
            ogdata = data

            let parsed = try carparser.parse(data)
            parsedentries = parsed

            entries = parsed.map {
                entry(
                    name: $0.name,
                    ogr: $0.ogr,
                    ogg: $0.ogg,
                    ogb: $0.ogb,
                    oga: $0.oga,
                    r: $0.ogr,
                    g: $0.ogg,
                    b: $0.ogb,
                    a: $0.oga
                )
            }

            status = "Loaded \(entries.count) colors"

        } catch {
            status = "Failed: \(error.localizedDescription)"
            print(error)
        }
    }

    func apply() {
        guard var original = ogdata else {
            status = "No original data"
            return
        }

        for i in 0..<parsedentries.count {
            parsedentries[i].r = entries[i].r
            parsedentries[i].g = entries[i].g
            parsedentries[i].b = entries[i].b
            parsedentries[i].a = entries[i].a
        }

        for e in parsedentries {
            original[e.coloroff]     = e.b
            original[e.coloroff + 1] = e.g
            original[e.coloroff + 2] = e.r
            original[e.coloroff + 3] = e.a
        }

        let tmp = NSTemporaryDirectory() + "patched.car"
        do {
            try original.write(to: URL(fileURLWithPath: tmp))
        } catch {
            status = "Temp write failed: \(error.localizedDescription)"
            return
        }

        let res = mgr.dsploit_overwritefile(target: syspath, source: tmp)
        status = res.ok ? "Patched!" : "Failed: \(res.message)"

        try? FileManager.default.removeItem(atPath: tmp)
    }
}
