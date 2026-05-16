//
//  LiquidGlassPreview.swift
//  DSPloit
//
//  Created by lunginspector on 5/13/26.
//

import SwiftUI

struct LiquidGlassPreview: View {
    @Binding var lgDisabled: Bool
    @Binding var lgFallback: Bool
    
    var body: some View {
        VStack(spacing: 20) {
            HStack(spacing: 12) {
                Image(systemName: "wrench.and.screwdriver")
                    .foregroundStyle(.white)
                    .frame(width: 45, height: 45)
                    .background(.blue)
                    .clipShape(.rect(cornerRadius: 14))
                VStack(alignment: .leading) {
                    Text("App Notification")
                        .fontWeight(.medium)
                    Text("This is a notification!")
                }
                .font(.system(size: 14))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .modifier(NotificationBG(lgDisabled: lgDisabled, lgFallback: lgFallback))
            
            HStack {
                Image(systemName: "flashlight.off.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 26, height: 26)
                    .padding()
                    .modifier(ActionBG(lgDisabled: lgDisabled, lgFallback: lgFallback))
                Spacer()
                Image(systemName: "camera.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 26, height: 26)
                    .padding()
                    .modifier(ActionBG(lgDisabled: lgDisabled, lgFallback: lgFallback))
            }
            .padding(.horizontal, 30)
            
            Capsule()
                .frame(width: 145, height: 4)
        }
        .foregroundStyle(.white)
        .padding(.horizontal)
        .padding(.top)
        .padding(.bottom, 10)
        .background {
            Image("solarium")
                .resizable()
                .scaledToFill()
                .brightness(-0.1)
        }
    }
}

struct ActionBG: ViewModifier {
    var lgDisabled: Bool
    var lgFallback: Bool
    
    func body(content: Content) -> some View {
        if lgDisabled || lgFallback {
            if lgFallback && !lgDisabled {
                content
                    .background(Color(.systemGray))
                    .clipShape(.capsule)
            } else {
                content
                    .background(.ultraThinMaterial)
                    .clipShape(.capsule)
            }
        } else {
            if #available(iOS 19.0, *) {
                content
                    .glassEffect(.clear.interactive(), in: .capsule)
            }
        }
    }
}

struct NotificationBG: ViewModifier {
    var lgDisabled: Bool
    var lgFallback: Bool
    
    func body(content: Content) -> some View {
        if lgDisabled || lgFallback {
            if lgFallback && !lgDisabled {
                content
                    .background(Color(.systemGray))
                    .clipShape(.rect(cornerRadius: 26))
            } else {
                content
                    .background(.black)
                    .clipShape(.rect(cornerRadius: 26))
            }
        } else {
            if #available(iOS 19.0, *) {
                content
                    .glassEffect(.clear, in: .rect(cornerRadius: 26))
            }
        }
    }
}
