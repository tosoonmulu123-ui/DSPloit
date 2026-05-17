//
//  PremiumEffects.swift
//  PartyUI
//
//  🔥 BLEEDING EDGE: Premium UI Effects & Animations
//  Glassmorphism, neon glow, particle effects, liquid animations
//  Created by Royan
//

import SwiftUI

// MARK: - Premium Styling Modifier (defined in HeaderLabel.swift)
// premiumStyling() is already available via PremiumListModifier

// MARK: - Premium Background

struct PremiumBackground: View {
    @State private var animateGradient = false
    
    var body: some View {
        ZStack {
            // Base dark gradient
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.02, blue: 0.05),
                    Color(red: 0.05, green: 0.03, blue: 0.08),
                    Color(red: 0.02, green: 0.02, blue: 0.05),
                ],
                startPoint: animateGradient ? .topLeading : .bottomTrailing,
                endPoint: animateGradient ? .bottomTrailing : .topLeading
            )
            .ignoresSafeArea()
            .onAppear {
                withAnimation(.easeInOut(duration: 8).repeatForever(autoreverses: true)) {
                    animateGradient.toggle()
                }
            }
            
            // Subtle accent orbs
            GeometryReader { geo in
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color.orange.opacity(0.05), Color.clear],
                            center: .center,
                            startRadius: 0,
                            endRadius: geo.size.width * 0.4
                        )
                    )
                    .frame(width: geo.size.width * 0.8)
                    .offset(x: -geo.size.width * 0.2, y: -geo.size.height * 0.1)
                
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color.purple.opacity(0.03), Color.clear],
                            center: .center,
                            startRadius: 0,
                            endRadius: geo.size.width * 0.3
                        )
                    )
                    .frame(width: geo.size.width * 0.6)
                    .offset(x: geo.size.width * 0.5, y: geo.size.height * 0.6)
            }
            .ignoresSafeArea()
        }
    }
}

// MARK: - Neon Glow Effect

struct NeonGlow: ViewModifier {
    let color: Color
    let radius: CGFloat
    
    func body(content: Content) -> some View {
        content
            .shadow(color: color.opacity(0.6), radius: radius)
            .shadow(color: color.opacity(0.3), radius: radius * 2)
    }
}

extension View {
    func neonGlow(_ color: Color, radius: CGFloat = 4) -> some View {
        modifier(NeonGlow(color: color, radius: radius))
    }
}

// MARK: - Glassmorphism Card

struct GlassCard: ViewModifier {
    let cornerRadius: CGFloat
    
    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: cornerRadius)
                            .stroke(
                                LinearGradient(
                                    colors: [
                                        Color.white.opacity(0.2),
                                        Color.white.opacity(0.05),
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                lineWidth: 0.5
                            )
                    )
            )
    }
}

extension View {
    func glassCard(cornerRadius: CGFloat = 16) -> some View {
        modifier(GlassCard(cornerRadius: cornerRadius))
    }
}

// MARK: - Pulse Animation

struct PulseAnimation: ViewModifier {
    @State private var isPulsing = false
    let color: Color
    
    func body(content: Content) -> some View {
        content
            .overlay(
                Circle()
                    .stroke(color.opacity(isPulsing ? 0 : 0.5), lineWidth: 2)
                    .scaleEffect(isPulsing ? 2.0 : 1.0)
                    .opacity(isPulsing ? 0 : 1)
                    .animation(.easeOut(duration: 1.5).repeatForever(autoreverses: false), value: isPulsing)
            )
            .onAppear { isPulsing = true }
    }
}

extension View {
    func pulseAnimation(color: Color = .orange) -> some View {
        modifier(PulseAnimation(color: color))
    }
}

// MARK: - Shimmer Effect

struct ShimmerEffect: ViewModifier {
    @State private var phase: CGFloat = 0
    
    func body(content: Content) -> some View {
        content
            .overlay(
                LinearGradient(
                    colors: [
                        Color.clear,
                        Color.white.opacity(0.1),
                        Color.clear,
                    ],
                    startPoint: .leading,
                    endPoint: .trailing
                )
                .offset(x: phase)
                .mask(content)
            )
            .onAppear {
                withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) {
                    phase = 300
                }
            }
    }
}

extension View {
    func shimmer() -> some View {
        modifier(ShimmerEffect())
    }
}

// MARK: - Status Indicator

struct LiveStatusIndicator: View {
    let isActive: Bool
    let activeColor: Color
    @State private var isAnimating = false
    
    var body: some View {
        ZStack {
            Circle()
                .fill(isActive ? activeColor : Color.gray)
                .frame(width: 8, height: 8)
            
            if isActive {
                Circle()
                    .stroke(activeColor.opacity(0.5), lineWidth: 1)
                    .frame(width: 14, height: 14)
                    .scaleEffect(isAnimating ? 1.5 : 1.0)
                    .opacity(isAnimating ? 0 : 1)
                    .animation(.easeOut(duration: 1.5).repeatForever(autoreverses: false), value: isAnimating)
                    .onAppear { isAnimating = true }
            }
        }
    }
}

// MARK: - Animated Counter

struct AnimatedCounter: View {
    let value: Int
    let font: Font
    let color: Color
    
    var body: some View {
        Text("\(value)")
            .font(font)
            .foregroundStyle(color)
            .contentTransition(.numericText())
            .animation(.spring(response: 0.3), value: value)
    }
}

// MARK: - Gradient Border

struct GradientBorder: ViewModifier {
    let colors: [Color]
    let lineWidth: CGFloat
    let cornerRadius: CGFloat
    
    func body(content: Content) -> some View {
        content
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(
                        LinearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing),
                        lineWidth: lineWidth
                    )
            )
    }
}

extension View {
    func gradientBorder(colors: [Color] = [.orange, .red, .purple], lineWidth: CGFloat = 1, cornerRadius: CGFloat = 12) -> some View {
        modifier(GradientBorder(colors: colors, lineWidth: lineWidth, cornerRadius: cornerRadius))
    }
}
