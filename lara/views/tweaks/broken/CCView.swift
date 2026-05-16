//
//  CCView.swift
//  DSPloit
//
//  Created by ruter on 16.04.26.
//

import SwiftUI

struct CCView: View {
    var body: some View {
        NavigationStack {
            List {
                Section {
                } header: {
                    Text("RespringCC")
                } footer: {
                    Text("Uses DSPloit's respring helper.")
                }
            }
            .navigationTitle("Control Center")
        }
    }
}
