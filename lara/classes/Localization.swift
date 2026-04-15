//
//  Localization.swift
//  lara
//
//  Created by Codex on 15.04.26.
//

import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    case english = "en"
    case indonesian = "id"
    
    var id: String { rawValue }
    
    var label: String {
        switch self {
        case .english: return "English"
        case .indonesian: return "Bahasa Indonesia"
        }
    }
}

@inline(__always)
func L(_ en: String, _ id: String) -> String {
    let raw = UserDefaults.standard.string(forKey: "app_language") ?? AppLanguage.english.rawValue
    return raw == AppLanguage.indonesian.rawValue ? id : en
}
