import Foundation
import Security

class PKCS12ImportLogger {
    static func logImportResult(_ items: CFArray?) {
        print("PKCS12 import operation completed successfully")

        if let items = items as? [[String: Any]], !items.isEmpty {
            print("Imported \(items.count) item(s)")
            for (index, item) in items.enumerated() {
                print("Item \(index + 1):")
                if let identity = item[kSecImportItemIdentity as String] as! SecIdentity? {
                    print("  - Identity found")
                    logCertificateInfo(identity)
                }
                if let trust = item[kSecImportItemTrust as String] as! SecTrust? {
                    logTrustInformation(trust)
                }
            }
        } else {
            print("No items were imported")
        }
    }

    static private func logCertificateInfo(_ identity: SecIdentity) {
        var cert: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &cert)
        if status == errSecSuccess, let cert = cert {
            let summary = SecCertificateCopySubjectSummary(cert) as String?
            print("    Certificate Subject: \(summary ?? "Unknown")")
        }
    }

    static private func logTrustInformation(_ trust: SecTrust) {
        let trustResult = SecTrustEvaluateWithError(trust, nil)
        print("    Trust Evaluation Result: \(trustResult ? "Trusted" : "Not Trusted")")

        if let certificateChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
           let leafCertificate = certificateChain.first {
            if let commonName = SecCertificateCopySubjectSummary(leafCertificate) as String? {
                print("    Common Name: \(commonName)")
            }
        }
    }
}
