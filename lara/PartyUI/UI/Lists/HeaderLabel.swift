//
//  HeaderLabel.swift
//  PartyUI
//
//  Created by lunginspector on 3/3/26.
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
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.secondary)
                .frame(width: width.headerIcon, alignment: .center)
            Text(text)
                .font(.system(.subheadline, design: .default, weight: .bold))
                .foregroundStyle(.primary)
                .textCase(nil) // Prevent automatic all-caps if the list forces it
        }
        .padding(.vertical, 4)
    }
}
