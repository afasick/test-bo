//
//  AccessToken.swift
//  CBSiAPI
//
//  Created by McDaniel, Forrest (really cool guy) on 11/23/16.
//  Copyright © 2016 CBS interactive. All rights reserved.
//

import Foundation
import CommonCrypto

protocol AppSecret {
    func accessToken() -> String
}

extension String: AppSecret {
    internal func accessToken() -> String {
        /*
         generate an iv
         */
        var iv: String {
            get {
                var i = String()
                for _ in 0 ..< 16 {
                    let digit = arc4random() % 10
                    i +=  "\(digit)"
                }
                return i
            }
        }
        /*
         create nonce from date
         */
        var nonce: String {
            get {
                let date = Date()
                let formatter = DateFormatter()
                formatter.timeZone = TimeZone(identifier: "UCT")
                formatter.dateFormat = "ss"
                let sec = Double(formatter.string(from: date))!
                formatter.dateFormat = "mm"
                let min = Double(formatter.string(from: date))!
                let timeInterval = date.timeIntervalSince1970
                return "\(timeInterval - min * 60.0 - sec)"
            }
        }
        /*
         apply cccryptor encoding, return base64 encoded string
         */
        func encrypt(string incoming: String) -> String {
            let inc = NSString(string: incoming)
            let incomingData = inc.data(using: String.Encoding.utf8.rawValue)!
            let key = "MCpqDXCn6bln+R05/vPjh4FuMJWSWuRTe86WBjMR+cU="
            let keyData = key.base64Decoded()
            let ivLocal = iv
            let ivData = ivLocal.data(using: String.Encoding.utf8)!
            let incomingBytes = NSData(data: incomingData).bytes
            let keyBytes = NSData(data: keyData).bytes
            let ivBytes = NSData(data: ivData).bytes
            let incomingLength = incoming.lengthOfBytes(using: String.Encoding.utf8)
            let ivLength = UInt16(ivLocal.lengthOfBytes(using: String.Encoding.utf8))
            let bufferSize = incomingLength + kCCBlockSizeAES128
            let buffer = malloc(bufferSize)
            var numBytesEncrypted = 0
            let cryptorStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding), keyBytes, kCCKeySizeAES256, ivBytes, incomingBytes, incomingLength, buffer, bufferSize, &numBytesEncrypted)
            var length = CFSwapInt16(ivLength)
            var result = Data(bytes: &length, count: MemoryLayout<UInt16>.size)
            result.append(ivData)
            if cryptorStatus == CCCryptorStatus(kCCSuccess) {
                let buff = Data(bytes: buffer!, count: numBytesEncrypted)
                result.append(buff)
                
            }
            free(buffer)
            return result.base64EncodedString()
        }
        let bn = Bundle.main.infoDictionary?["CFBundleVersion"] as! String
        let vn = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as! String
        let encrypted = encrypt(string: String(format: "%@|%@|%@|%@", nonce, self, vn, bn))
        return encrypted
    }
    //: ### Base64 encoding a string
    fileprivate func base64Encoded() -> String? {
        if let data = self.data(using: .utf8) {
            return data.base64EncodedString()
        }
        return nil
    }
    
    //: ### Base64 decoding a string
    fileprivate func base64Decoded() -> Data {
        let data = Data(base64Encoded: self)!
        return data
    }
}











