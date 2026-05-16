//
//  keepalive.swift
//  DSPloit
//
//  Created by ruter on 29.03.26.
//

import AVFoundation

private var kaplayer: AVAudioPlayer?
var kaenabled = false

func toggleka() {
    if kaenabled {
        kaplayer?.stop()
        kaplayer = nil
        kaenabled = false
        globallogger.log("(ka) disabled keepalive")
        
        return
    }
    
    do {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
        try session.setActive(true)
    } catch {
        globallogger.log("(ka) audio session failed: \(error)")
        return
    }

    let fileurl = getwavurl()
    
    if !FileManager.default.fileExists(atPath: fileurl.path) {
        makesilentwav(at: fileurl)
    }
    
    do {
        kaplayer = try AVAudioPlayer(contentsOf: fileurl)
        kaplayer?.numberOfLoops = -1
        kaplayer?.volume = 0.0
        kaplayer?.prepareToPlay()
        kaplayer?.play()
        kaenabled = true
        globallogger.log("(ka) enabled keepalive")
    } catch {
        globallogger.log("(ka) audio failed: \(error)")
    }
}

private func getwavurl() -> URL {
    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    return docs.appendingPathComponent("silent.wav")
}

private func makesilentwav(at url: URL) {
    let samplerate = 44100
    let duration = 1
    let numsamples = samplerate * duration
    
    var wavdata = Data()
    
    let byterate = samplerate * 2
    let blockalign: UInt16 = 2
    let datasize = numsamples * 2
    let chunksize = 36 + datasize
    
    func append<T>(_ value: T) {
        var v = value
        withUnsafeBytes(of: &v) { bytes in
            wavdata.append(contentsOf: bytes)
        }
    }
    
    wavdata.append("RIFF".data(using: .ascii)!)
    append(UInt32(chunksize))
    wavdata.append("WAVE".data(using: .ascii)!)
    
    wavdata.append("fmt ".data(using: .ascii)!)
    append(UInt32(16))
    append(UInt16(1))
    append(UInt16(1))
    append(UInt32(samplerate))
    append(UInt32(byterate))
    append(blockalign)
    append(UInt16(16))
    
    wavdata.append("data".data(using: .ascii)!)
    append(UInt32(datasize))
    
    wavdata.append(Data(count: datasize))
    
    try? wavdata.write(to: url)
}
