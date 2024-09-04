import SwiftUI
import Foundation
import Security

class PKCS12ImportViewModel: ObservableObject {
    @Published var isImportSuccessful: Bool = false
    @Published var errorMessage: String?

    private let fileName = "SAMPLE"
    private let fileType = "p12"
    private let passphrase = "12345678"

    func executePKCS12ImportProcess() {
        Task {
            do {
                let data = try await createPKCS12()
                savePKCS12DataToFile(data)
                importPKCS12(data)
                await MainActor.run {
                    self.isImportSuccessful = true
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = "Error obtaining user identity: \(error.localizedDescription)"
                }
            }
        }
    }

    private func createPKCS12() async throws -> Data {
        let fileData = try loadFileData(fileName: fileName, fileType: fileType)
        let opensslWrapper = OpenSSLCryptoOperationsWrapper()

        guard let pkcs12Data = opensslWrapper.createPKCS12(fromPKCS12Data: fileData,
                                                           originalPassphrase: passphrase,
                                                           newPassphrase: "",
                                                           name: "Friendly name") else {
            throw NSError(domain: "PKCS12Error", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create PKCS12 data"])
        }

        return pkcs12Data
    }

    private func loadFileData(fileName: String, fileType: String) throws -> Data {
        guard let path = Bundle.main.path(forResource: fileName, ofType: fileType) else {
            throw NSError(domain: "FileError", code: 0, userInfo: [NSLocalizedDescriptionKey: "File not found"])
        }

        let fileURL = URL(fileURLWithPath: path)
        return try Data(contentsOf: fileURL)
    }

    private func savePKCS12DataToFile(_ data: Data) {
        let fileManager = FileManager.default
        let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsDirectory.appendingPathComponent("pkcs12_data.p12")

        do {
            try data.write(to: fileURL)
            print("PKCS12 data saved successfully locally")
            print("File saved at: \(fileURL.path)")
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
            PKCS12ImportLogger.logImportResult(items)
        } else {
            handleFailedImport(err)
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
