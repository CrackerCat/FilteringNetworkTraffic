/*
See LICENSE folder for this sample’s licensing information.

Abstract:
This file contains the implementation of the NEFilterDataProvider sub-class.
*/

import NetworkExtension
import os
import os.log
import Darwin.bsm

// Main structure for events. Uses Codable for painless serialization.
public struct NetworkEvent: Codable {
    public var eventtype: String
    
    public var pid: Int32
    public var uid: Int32
    public var gid: Int32
    public var processpath: String
    
    public var localHostName: String
    public var localPort: String
    public var remoteHostName: String
    public var remotePort: String
    public var direction: String
    public var socketFamily: String
    public var socketType: String
    public var socketProtocol: String
    public var packets: String

    public var description: String {
        let pretty = """
        Event Type: \(eventtype)
        Process: \(processpath)
        Pid: \(pid)
        Uid: \(uid)
        Gid: \(gid)
        localHostName: \(localHostName)
        localPort: \(localPort)
        remoteHostName: \(remoteHostName)
        remotePort: \(remotePort)
        direction: \(direction)
        socketFamily: \(socketFamily)
        socketType: \(socketType)
        socketProtocol: \(socketProtocol)
        packets: \(packets)
        """
        return pretty
    }

    init() {
        eventtype = ""
        processpath = ""
        pid = -1
        uid = -1
        gid = -1
        localHostName = ""
        localPort = ""
        remotePort = ""
        remoteHostName = ""
        direction = ""
        socketFamily = ""
        socketType = ""
        socketProtocol = ""
        packets = ""
    }
}



func getSocketFamily(family: Int32) -> String {
    switch family {
    case AF_INET:   return "AF_INET";
    case AF_INET6:  return "AF_INET6";
    default:        return "UNKNOWN";
    }
}

func getSocketType(type: Int32) -> String {
    switch type {
    case SOCK_STREAM:       return "SOCK_STREAM";
    case SOCK_DGRAM:        return "SOCK_DGRAM";
    case SOCK_RAW:          return "SOCK_RAW";
    case SOCK_RDM:          return "SOCK_RDM";
    case SOCK_SEQPACKET:    return "SOCK_SEQPACKET";
    default:                return "UNKNOWN";
    }
}

func getSocketProtocol(_protocol: Int32) -> String {
    switch _protocol {
    case IPPROTO_IP:        return "IPPROTO_IP";
    case IPPROTO_ICMP:      return "IPPROTO_ICMP";
    case IPPROTO_IPV4:      return "IPPROTO_IPV4";
    case IPPROTO_TCP:       return "IPPROTO_TCP";
    case IPPROTO_UDP:       return "IPPROTO_UDP";
    case IPPROTO_IPV6:      return "IPPROTO_IPV6";
    case IPPROTO_ICMPV6:    return "IPPROTO_ICMPV6";
    case IPPROTO_RAW:       return "IPPROTO_RAW";
    default:                return "UNKNOWN";
    }
}

func getflowDirection(direct: NETrafficDirection) -> String {
    switch direct {
    case NETrafficDirection.any:        return "Any";
    case NETrafficDirection.inbound:    return "Inbound";
    case NETrafficDirection.outbound:   return "Outbound";
    default:                            return "Unknown";
    }
}

// reference: https://developer.apple.com/forums/thread/122482
extension NEFilterFlow {

    /// A wrapper around `sourceAppAuditToken` that returns a value of the right type.
    ///
    /// - Note: I’d normally write this code in a much more compact fashion but
    /// I’ve expanded it out so that I can comment each step.

    var sourceAppAuditTokenQ: audit_token_t? {

        // The following lines check whether the `sourceAppAuditToken` value is
        // missing, returning `nil` in that case.
        //
        // The size check is a good idea in general, but it’s particularly
        // important because of the way that we set up `pRaw`.  See the comments
        // below for more details.

        guard
            let tokenData = self.sourceAppAuditToken,
            tokenData.count == MemoryLayout<audit_token_t>.size
        else {
            return nil
        }

        // Here we use `withUnsafeBytes(_:)` to call a closure (the stuff inside
        // the curly brackets) with an `UnsafeRawBufferPointer` that represents
        // the bytes in the `tokenData` value.  This `buf` value is, as the type
        // name suggests, a way to represent a buffer of raw bytes.

        return tokenData.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> audit_token_t in

            // Here we set `pRaw` to a pointer to the base address of that
            // buffer.  Note the force unwrap (`!`).  That’s necessary because
            // `buf.baseAddress` is optional, that is, it might be `nil`.  That
            // can only happen if the buffer is empty.  Thus, this force unwrap
            // is safe because of the size check that we did earlier.

            let pRaw = buf.baseAddress!

            // He we convert the raw pointer to a typed pointer.  The
            // `assumingMemoryBound(to:)` routine is something that you should
            // approach with _extreme_ caution.  See its doc comments for an
            // explanation as to why.  In this case, however, its the right
            // thing to do, because the framework guarantees that the buffer
            // contains an valid `audit_token_t`.

            let pToken = pRaw.assumingMemoryBound(to: audit_token_t.self)

            // He we dereference our typed pointer to get the actual value.

            let result = pToken.pointee

            // Finally, we return that value from our closure.  This becomes the
            // result of the `withUnsafeBytes(_:)` call, which ultimately
            // becomes the result of our property getter.

            return result
        }
    }
    
    var pid: pid_t {
        return audit_token_to_pid(self.sourceAppAuditTokenQ!)

    }

    var uid: uid_t {
        return audit_token_to_ruid(self.sourceAppAuditTokenQ!)

    }

    var gid: gid_t {
        return audit_token_to_rgid(self.sourceAppAuditTokenQ!)

    }
    var processPath: String? {
        var codeQ: SecCode? = nil

        var err = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: self.sourceAppAuditToken as Any] as NSDictionary, [], &codeQ)

        guard err == errSecSuccess else {
            return nil

        }

        let code = codeQ!

        var staticCodeQ: SecStaticCode? = nil

        err = SecCodeCopyStaticCode(code, [], &staticCodeQ) // Convert that to a static code.

        guard err == errSecSuccess else {
            return nil

        }

        let staticCode = staticCodeQ!

        var pathCodeQ: CFURL?

        err = SecCodeCopyPath(staticCode, SecCSFlags(rawValue: 0), &pathCodeQ);

        guard err == errSecSuccess else {
            return nil

        }



        let posixPath = CFURLCopyFileSystemPath(pathCodeQ, CFURLPathStyle.cfurlposixPathStyle);

        let posixPathStr: String = (posixPath! as NSString) as String

        //strdup(CFStringGetCStringPtr(posixPath, CFStringBuiltInEncodings.UTF8.rawValue));

        return posixPathStr

    }


}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}


/**
    The FilterDataProvider class handles connections that match the installed rules by prompting
    the user to allow or deny the connections.
 */
class FilterDataProvider: NEFilterDataProvider {

    // MARK: Properties

    // The TCP port which the filter is interested in.
	static let localPort = "8888"

    // MARK: NEFilterDataProvider

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {

        // Add code to initialize the filter.
        completionHandler(nil)
    }
    
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Add code to clean up filter resources.
        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // Add code to determine if the flow should be dropped or not, downloading new rules if required.
        return .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 1024, filterOutbound: false, peekOutboundBytes: 1)
    }
    
    
    
    override func handleInboundData(from flow: NEFilterFlow,
                                    readBytesStartOffset offset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint,
              let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint else {
//              let flowUrl = flow.url as URL?,
//              let identifier = flow.identifier as? UUID else {
                return .allow()
        }
        
        var nEvent = NetworkEvent()
        
        nEvent.eventtype = "network::flow"
        nEvent.localHostName = localEndpoint.hostname
        nEvent.localPort = localEndpoint.port
        nEvent.remoteHostName = remoteEndpoint.hostname
        nEvent.remotePort = remoteEndpoint.port
        nEvent.direction = getflowDirection(direct: socketFlow.direction)
        nEvent.socketFamily = getSocketFamily(family: socketFlow.socketFamily)
        nEvent.socketType =  getSocketType(type: socketFlow.socketType)
        nEvent.socketProtocol = getSocketProtocol(_protocol: socketFlow.socketProtocol)

        nEvent.pid = flow.pid
        nEvent.uid = Int32(flow.uid)
        nEvent.gid = Int32(flow.gid)
        nEvent.processpath = flow.processPath!
        nEvent.packets = readBytes.hexEncodedString()
        
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        guard let data = try? encoder.encode(nEvent)
        else {
            NSLog("Failed to seralize event")
            return .allow()
        }
        guard let json = String(data: data, encoding: .utf8) else {
            NSLog("Invalid json encode.")
            return .allow()
        }

        IPCConnection.shared.sendEventToApp(newEvent: json)
        return .allow()
    }
}
