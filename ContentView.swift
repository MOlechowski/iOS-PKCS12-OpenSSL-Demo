import SwiftUI
import Foundation

struct ContentView: View {
    @State private var pkcs12Data: Data?
    @State private var errorMessage: String?

    private let fileName = "SAMPLE"
    private let fileType = "p12"
    private let passphrase = "12345678"

    var body: some View {
        VStack {
            Button("Execute PKCS12 Import") {
                executePKCS12ImportProcess()
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

    private func executePKCS12ImportProcess() {
        DispatchQueue.global(qos: .userInitiated).async {
            importPKCS12 { result in
                switch result {
                case .success(let data):
                    self.pkcs12Data = data
                    savePKCS12DataToFile(data)
                    importPKCS12(data)
                case .failure(let error):
                    self.errorMessage = "Error obtaining user identity: \(error.localizedDescription)"
                }
            }
        }
    }

    private func importPKCS12(completionHandler: @escaping (Result<Data, Error>) -> Void) {
        guard let path = Bundle.main.path(forResource: fileName, ofType: fileType) else {
            completionHandler(.failure(NSError(domain: "FileError", code: 0, userInfo: [NSLocalizedDescriptionKey: "File not found"])))
            return
        }

        let fileURL = URL(fileURLWithPath: path)

        do {
            let data = try Data(contentsOf: fileURL)
            let opensslProxy = OpenSSLCryptoOperationsWrapper()

            guard let pkcs12Data = opensslProxy.createPKCS12(fromPKCS12Data: data,
                                                             originalPassphrase: passphrase,
                                                             newPassphrase: "",
                                                             name: "Friendly name") else {
                completionHandler(.failure(NSError(domain: "PKCS12Error", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create PKCS12 data"])))
                return
            }

            completionHandler(.success(pkcs12Data))
        } catch {
            completionHandler(.failure(error))
        }
    }

    private func savePKCS12DataToFile(_ data: Data) {
        let fileManager = FileManager.default
        let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsDirectory.appendingPathComponent("pkcs12_data.p12")

        do {
            try data.write(to: fileURL)
            print("PKCS12 data saved to: \(fileURL.path)")
        } catch {
            self.errorMessage = "Error saving PKCS12 data to file: \(error.localizedDescription)"
        }
    }

    private func importPKCS12(_ data: Data) {
        let query: [String: Any] = [
            kSecImportExportPassphrase as String: "",  // Empty string as passphrase
        ]

        var items: CFArray?
        let err = SecPKCS12Import(data as CFData, query as CFDictionary, &items)

        if err == errSecSuccess {
            handleSuccessfulImport(items)
        } else {
            handleFailedImport(err)
        }
    }

    private func handleSuccessfulImport(_ items: CFArray?) {
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
    }

    private func handleFailedImport(_ err: OSStatus) {
        self.errorMessage = "Error in SecPKCS12Import: \(err)"
        if let error = err.error {
            print("Error description: \(error.localizedDescription)")
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
