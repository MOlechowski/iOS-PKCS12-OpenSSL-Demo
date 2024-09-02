import SwiftUI
import Foundation
import Security

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
        Task {
            do {
                let data = try await importPKCS12()
                await MainActor.run {
                    self.pkcs12Data = data
                }
                savePKCS12DataToFile(data)
                importPKCS12(data)
            } catch {
                await MainActor.run {
                    self.errorMessage = "Error obtaining user identity: \(error.localizedDescription)"
                }
            }
        }
    }

    private func importPKCS12() async throws -> Data {
        guard let path = Bundle.main.path(forResource: fileName, ofType: fileType) else {
            throw NSError(domain: "FileError", code: 0, userInfo: [NSLocalizedDescriptionKey: "File not found"])
        }

        let fileURL = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: fileURL)
        let opensslProxy = OpenSSLCryptoOperationsWrapper()

        guard let pkcs12Data = opensslProxy.createPKCS12(fromPKCS12Data: data,
                                                         originalPassphrase: passphrase,
                                                         newPassphrase: "",
                                                         name: "Friendly name") else {
            throw NSError(domain: "PKCS12Error", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create PKCS12 data"])
        }

        return pkcs12Data
    }

    private func savePKCS12DataToFile(_ data: Data) {
        let fileManager = FileManager.default
        let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsDirectory.appendingPathComponent("pkcs12_data.p12")

        do {
            try data.write(to: fileURL)
            print("PKCS12 data saved successfully")
        } catch {
            self.errorMessage = "Error saving PKCS12 data to file: \(error.localizedDescription)"
        }
    }

    private func importPKCS12(_ data: Data) {
        let query: [String: Any] = [
            kSecImportExportPassphrase as String: "",
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

        if let items = items as? [[String: Any]], !items.isEmpty {
            print("Imported \(items.count) item(s)")
            for (index, item) in items.enumerated() {
                print("Item \(index + 1):")
                if let identity = item[kSecImportItemIdentity as String] as! SecIdentity? {
                    print("  - Identity found")
                    printCertificateInfo(identity)
                }
                if let trust = item[kSecImportItemTrust as String] as! SecTrust? {
                    printTrustInformation(trust)
                }
            }
        } else {
            print("No items were imported")
        }
    }

    private func printCertificateInfo(_ identity: SecIdentity) {
        var cert: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &cert)
        if status == errSecSuccess, let cert = cert {
            let summary = SecCertificateCopySubjectSummary(cert) as String?
            print("    Certificate Subject: \(summary ?? "Unknown")")
        }
    }

    private func printTrustInformation(_ trust: SecTrust) {
        let trustResult = SecTrustEvaluateWithError(trust, nil)
        print("    Trust Evaluation Result: \(trustResult ? "Trusted" : "Not Trusted")")

        if let certificateChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
           let leafCertificate = certificateChain.first {
            if let commonName = SecCertificateCopySubjectSummary(leafCertificate) as String? {
                print("    Common Name: \(commonName)")
            }
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
