import Foundation

/// The HTTP layer under the API client, so tests can answer requests themselves.
public struct HttpRequest: Sendable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?
}

public struct HttpResponse: Sendable {
    public var status: Int
    /// Header names in lower case.
    public var headers: [String: String]
    public var body: Data

    public init(status: Int, headers: [String: String], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// Sends a request and returns any status. Throws only when there is no response.
public protocol Transport: Sendable {
    func send(_ request: HttpRequest, timeout: TimeInterval) async throws -> HttpResponse
}

/// URLSession without cookies, caches or redirects to other origins.
public final class URLSessionTransport: Transport {
    private let session: URLSession

    public init() {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpMaximumConnectionsPerHost = 4
        session = URLSession(configuration: config)
    }

    public func send(_ request: HttpRequest, timeout: TimeInterval) async throws -> HttpResponse {
        var r = URLRequest(url: request.url, timeoutInterval: timeout)
        r.httpMethod = request.method
        for (k, v) in request.headers { r.setValue(v, forHTTPHeaderField: k) }
        r.httpBody = request.body
        let (data, response) = try await session.data(for: r)
        guard let http = response as? HTTPURLResponse else { throw ConnectionError("Not an HTTP response.") }
        var headers: [String: String] = [:]
        for (k, v) in http.allHeaderFields {
            if let k = k as? String, let v = v as? String { headers[k.lowercased()] = v }
        }
        return HttpResponse(status: http.statusCode, headers: headers, body: data)
    }
}
