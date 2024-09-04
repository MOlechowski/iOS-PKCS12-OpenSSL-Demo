import SwiftUI
import Foundation
import Security

struct ContentView: View {
    @StateObject private var viewModel = PKCS12ImportViewModel()

    var body: some View {
        VStack {
            Button("Execute PKCS12 Import") {
                viewModel.executePKCS12ImportProcess()
            }

            if let errorMessage = viewModel.errorMessage {
                Text("Error: \(errorMessage)")
                    .foregroundColor(.red)
            }

            if let pkcs12Data = viewModel.pkcs12Data {
                Text("Succesfully imported pkcs \n check console for more info")
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
