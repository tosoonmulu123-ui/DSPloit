//
//  AppInfoCell.swift
//  DSPloit
//

import SwiftUI

public struct AppInfoCell: View {
    public init() {}
    
    public var body: some View {
        HStack(spacing: 12) {
            AppIcon()
            VStack(alignment: .leading, spacing: 2) {
                Text(AppInfo.appName)
                    .font(.system(size: 15, weight: .semibold))
                Text("v\(AppInfo.appVersion) (\(AppInfo.appBuild))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
    }
}

public struct AppIcon: View {
    var image: Image
    
    init(image: Image = Image(uiImage: AppInfo.appIcon ?? UIImage())) {
        self.image = image
    }
    
    public var body: some View {
        image
            .resizable()
            .scaledToFit()
            .frame(width: 48, height: 48)
            .clipShape(RoundedRectangle(cornerRadius: 11))
    }
}
