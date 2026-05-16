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
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(LinearGradient(colors: [Color.indigo.opacity(0.5), Color.purple.opacity(0.3)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 32, height: 32)
                    .shadow(color: Color.indigo.opacity(0.4), radius: 4, x: 0, y: 2)
                
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(LinearGradient(colors: [.white, .white.opacity(0.8)], startPoint: .top, endPoint: .bottom))
            }
            
            Text(text)
                .font(.system(.title3, design: .rounded, weight: .bold))
                .foregroundStyle(LinearGradient(colors: [.primary, .primary.opacity(0.8)], startPoint: .topLeading, endPoint: .bottomTrailing))
                .textCase(nil)
        }
        .padding(.vertical, 8)
    }
}

// MARK: - Premium Design Tokens

public struct DarkGlassBackground: View {
    public init() {}
    public var body: some View {
        ZStack {
            Color(UIColor.systemBackground).ignoresSafeArea()
            
            // Subtle ambient glows
            Circle()
                .fill(Color.purple.opacity(0.15))
                .blur(radius: 60)
                .frame(width: 300, height: 300)
                .offset(x: -100, y: -200)
            
            Circle()
                .fill(Color.indigo.opacity(0.15))
                .blur(radius: 60)
                .frame(width: 300, height: 300)
                .offset(x: 150, y: 300)
                
            Circle()
                .fill(Color.blue.opacity(0.1))
                .blur(radius: 80)
                .frame(width: 400, height: 400)
                .offset(x: -50, y: 100)
        }
        .ignoresSafeArea()
    }
}

public struct PremiumListModifier: ViewModifier {
    public func body(content: Content) -> some View {
        content
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(DarkGlassBackground())
            .preferredColorScheme(.dark)
            .tint(Color.indigo)
    }
}

extension View {
    public func premiumStyling() -> some View {
        self.modifier(PremiumListModifier())
    }
}
