import SwiftUI
import Foundation

struct ContentView: View {
    @State private var pkcs12Data: Data?
    @State private var errorMessage: String?

    let fileName = "SAMPLE"
    let fileType = "p12"
    let passphrase = "12345678"

    var body: some View {
        VStack {
            Button("Check Apple API") {
                checkTheAppleAPI()
            }

            if let errorMessage = errorMessage {
                Text("Error: \(errorMessage)")
                    .foregroundColor(.red)
            }

            if let pkcs12Data = pkcs12Data {
                Text("PKCS12 data size: \(pkcs12Data.count) bytes")
            }
        }
        .padding()
    }

    private func checkTheAppleAPI() {
        obtainUserIdentity { data, error in
            if let error = error {
                self.errorMessage = "Error obtaining user identity: \(error.localizedDescription)"
                return
            }

            guard let pkcs12Data = data else {
                self.errorMessage = "No PKCS12 data obtained"
                return
            }

            self.pkcs12Data = pkcs12Data

            // Save PKCS12 data to file
            let fileManager = FileManager.default
            let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let fileURL = documentsDirectory.appendingPathComponent("pkcs12_data.p12")

            do {
                try pkcs12Data.write(to: fileURL)
                print("PKCS12 data saved to: \(fileURL.path)")
            } catch {
                self.errorMessage = "Error saving PKCS12 data to file: \(error.localizedDescription)"
                return
            }

            let query: [String: Any] = [
                kSecImportExportPassphrase as String: "",  // Empty string as passphrase
            ]

            var items: CFArray?
            let err = SecPKCS12Import(pkcs12Data as CFData, query as CFDictionary, &items)

            if err == errSecSuccess {
                print("PKCS12 import operation completed successfully")
                if let items = items as? [[String: Any]] {
                    print("Imported \(items.count) item(s)")
                    if items.isEmpty {
                        self.errorMessage = "Warning: No items were imported despite successful operation"
                    } else {
                        for (index, item) in items.enumerated() {
                            print("Item \(index + 1):")
                            if let certChain = item[kSecImportItemCertChain as String] as? [SecCertificate] {
                                print("  - Certificate chain found with \(certChain.count) certificate(s)")
                            }
                        }
                    }
                } else {
                    self.errorMessage = "Warning: Items array is nil despite successful operation"
                }
            } else {
                self.errorMessage = "Error in SecPKCS12Import: \(err)"
                if let error = err.error {
                    print("Error description: \(error.localizedDescription)")
                }
            }
        }
    }

    private func obtainUserIdentity(completionHandler: @escaping (Data?, Error?) -> Void) {
        guard let path = Bundle.main.path(forResource: fileName, ofType: fileType) else {
            completionHandler(nil, NSError(domain: "FileError", code: 0, userInfo: [NSLocalizedDescriptionKey: "File not found"]))
            return
        }

        let fileURL = URL(fileURLWithPath: path)

        do {
            let data = try Data(contentsOf: fileURL)
            let opensslProxy = OpenSSlWrapper()

            guard let pkcs12Data = opensslProxy.createPKCS12(fromPKCS12Data: data,
                                                             originalPassphrase: passphrase,
                                                             newPassphrase: "",
                                                             name: "Friendly name") else {
                completionHandler(nil, NSError(domain: "PKCS12Error", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create PKCS12 data"]))
                return
            }

            completionHandler(pkcs12Data, nil)
        } catch {
            completionHandler(nil, error)
        }
    }
}

extension OSStatus {
    var error: NSError? {
        guard self != errSecSuccess else { return nil }

        let message = SecCopyErrorMessageString(self, nil) as String? ?? "Unknown error"

        return NSError(domain: NSOSStatusErrorDomain, code: Int(self), userInfo: [
            NSLocalizedDescriptionKey: message])
    }
}

#Preview {
    ContentView()
}
