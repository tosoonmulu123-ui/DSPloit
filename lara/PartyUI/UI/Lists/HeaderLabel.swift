//
//  HeaderLabel.swift
//  DSPloit
//

import SwiftUI

public struct HeaderLabel: View {
    var text: String
    var icon: String
    
    public init(text: String, icon: String) {
        self.text = text
        self.icon = icon
    }
    
    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
            Text(text.uppercased())
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .textCase(nil)
        }
    }
}

public struct PremiumListModifier: ViewModifier {
    public func body(content: Content) -> some View {
        content
            .listStyle(.insetGrouped)
    }
}

extension View {
    public func premiumStyling() -> some View {
        self.modifier(PremiumListModifier())
    }
}
