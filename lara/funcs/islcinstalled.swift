//
//  islcinstalled.swift
//  DSPloit
//
//  Created by ruter on 30.03.26.
//

import Foundation

func islcinstalled() -> Bool {
    if Bundle.main.path(forResource: "LCAppInfo", ofType: "plist") != nil {
        globallogger.log("\nlivecontainer detected: yeah (LCAppInfo.plist)")
        return true
    }

    globallogger.log("\nlivecontainer detected: nah")
    return false
}
