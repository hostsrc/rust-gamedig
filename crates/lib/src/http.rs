//! Client for making HTTP requests.
//!
//! This is the first draft implementation: feel free to change things to suit
//! your needs.

// Because this is first draft some functionality is not used yet.
// TODO: When this is used in more places remove this and refine the interface.
#![allow(dead_code)]

use crate::utils::{read_to_end_capped, MAX_STREAM_RESPONSE};
use crate::GDErrorKind::{HostLookup, InvalidInput, PacketSend, ProtocolFormat};
use crate::{GDResult, TimeoutSettings};

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use ureq::{Agent, AgentBuilder, Request, Response};
use url::{Host, Url};

use serde::{de::DeserializeOwned, Serialize};

/// Max length of HTTP response bodies in bytes: 1 MiB. A longer body is a
/// [PacketOverflow](crate::GDErrorKind::PacketOverflow) error.
const MAX_RESPONSE_LENGTH: usize = MAX_STREAM_RESPONSE;

/// Read a response body, at most [MAX_RESPONSE_LENGTH] bytes.
fn read_body(http_response: Response) -> GDResult<Vec<u8>> {
    let length = match http_response.header("Content-Length") {
        Some(length) => {
            length
                .parse::<usize>()
                .map_err(|e| ProtocolFormat.context(e))?
        }
        None => 5012, // Sensible default allocation
    };

    read_to_end_capped(http_response.into_reader(), length, MAX_RESPONSE_LENGTH)
}

/// Read a response body (capped as [read_body]) and parse it as JSON.
fn read_json<T: DeserializeOwned>(http_response: Response) -> GDResult<T> {
    let body = read_body(http_response)?;
    serde_json::from_slice(&body).map_err(|e| ProtocolFormat.context(e))
}

/// HTTP request client. Define parameters host parameters on new, then re-use
/// for each request.
///
/// When making requests directly to the server use [HttpClient::new] as this
/// allows directly specifying the IP to connect to.
///
/// When requests must go through an intermediatary (that we don't know the IP
/// of) use [HttpClient::from_url] which will perform a DNS lookup internally.
///
/// For example usage see [tests].
pub struct HttpClient {
    client: Agent,
    address: Url,
    headers: Vec<(String, String)>,
}

/// HttpHeaders for use with a single request.
pub type HttpHeaders<'a> = Option<&'a [(&'a str, &'a str)]>;

/// HTTP Protocols.
///
/// Note: if the `tls` feature is disabled this will only contain Http.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum HttpProtocol {
    #[default]
    Http,
    #[cfg(feature = "tls")]
    Https,
}

impl HttpProtocol {
    /// Convert [Protocol] to a static str for use in a [Url].
    /// e.g. "http:"
    pub const fn as_str(&self) -> &'static str {
        use HttpProtocol::*;
        match self {
            Http => "http:",
            #[cfg(feature = "tls")]
            Https => "https:",
        }
    }
}

/// Additional settings for HTTPClients.
///
/// # Can be created using builder functions:
/// ```ignore, We cannot test private functionality
/// use gamedig::http::{HttpSettings, HttpProtocol};
///
/// let _ = HttpSettings::default()
///   .protocol(HttpProtocol::Http)
///   .hostname(String::from("test.com"))
///   .header(String::from("Authorization"), String::from("Bearer Token"));
/// ```
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct HttpSettings<S: Into<String>> {
    /// Choose whether to use HTTP or HTTPS.
    pub protocol: HttpProtocol,
    /// Choose a hostname override (used to set the [Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) header) and for TLS.
    pub hostname: Option<S>,
    /// Choose HTTP headers to send with requests.
    pub headers: Vec<(S, S)>,
}

impl<S: Into<String>> HttpSettings<S> {
    /// Set the HTTP protocol (defaults to HTTP).
    pub const fn protocol(mut self, protocol: HttpProtocol) -> HttpSettings<S> {
        self.protocol = protocol;
        self
    }

    /// Set the desired HTTP host name: used for the HTTP Host header and for
    /// TLS negotiation.
    pub fn hostname(mut self, hostname: S) -> HttpSettings<S> {
        self.hostname = Some(hostname);
        self
    }

    /// Overwrite all the current HTTP headers with new headers.
    pub fn headers(mut self, headers: Vec<(S, S)>) -> HttpSettings<S> {
        self.headers = headers;
        self
    }

    /// Set one HTTP header value.
    pub fn header(mut self, name: S, value: S) -> HttpSettings<S> {
        self.headers.push((name, value));
        self
    }
}

impl HttpClient {
    /// Creates a new HTTPClient that can be used to send requests.
    ///
    /// # Parameters
    /// - [address](SocketAddr): The IP and port the HTTP request will connect
    ///   to.
    /// - [timeout_settings](TimeoutSettings): Used to set the connect and
    ///   socket timeouts for the requests.
    /// - [http_settings](HttpSettings): Additional settings for the HTTPClient.
    pub fn new<S: Into<String>>(
        address: &SocketAddr,
        timeout_settings: &Option<TimeoutSettings>,
        http_settings: HttpSettings<S>,
    ) -> GDResult<Self>
    where
        Self: Sized,
    {
        let mut client_builder = AgentBuilder::new();

        // Set timeout settings
        let (read_timeout, write_timeout) = TimeoutSettings::get_read_and_write_or_defaults(timeout_settings);

        if let Some(read_timeout) = read_timeout {
            client_builder = client_builder.timeout_read(read_timeout);
        }

        if let Some(write_timeout) = write_timeout {
            client_builder = client_builder.timeout_write(write_timeout);
        }

        if let Some(connect_timeout) = TimeoutSettings::get_connect_or_default(timeout_settings) {
            client_builder = client_builder.timeout_connect(connect_timeout);
        }

        // Every request sent from this client will connect to the address set
        {
            let address = *address;
            client_builder = client_builder.resolver(move |_: &str| Ok(vec![address]));
        }

        // Set a friendly user-agent string
        client_builder = client_builder.user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ));

        let client = client_builder.build();

        let host = http_settings
            .hostname
            .map(S::into)
            .unwrap_or_else(|| address.ip().to_string());

        Ok(Self {
            client,
            // TODO: Use Url from_parts if it gets added
            address: Url::parse(&format!(
                "{}//{}:{}",
                http_settings.protocol.as_str(),
                host,
                address.port()
            ))
            .map_err(|e| InvalidInput.context(e))?,
            headers: http_settings
                .headers
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        })
    }

    /// Create a new HTTP client from a pre-existing URL, performing a DNS
    /// lookup on the host when necessary.
    ///
    /// This is aimed to be used when we know the domain of the server but not
    /// the IP i.e. when the server is not the service being directly queried
    /// for server info.
    pub fn from_url<U: TryInto<Url>>(
        url: U,
        timeout_settings: &Option<TimeoutSettings>,
        headers: Option<Vec<(&str, &str)>>,
    ) -> GDResult<Self>
    where
        U::Error: std::error::Error + Send + Sync + 'static,
    {
        let url: Url = url.try_into().map_err(|e| InvalidInput.context(e))?;

        let host = url
            .host()
            .ok_or_else(|| InvalidInput.context("URL used to create a HTTPClient must have a host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| InvalidInput.context("URL used to create HttpClient must have a port"))?;

        let address = match host {
            Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
            Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            Host::Domain(domain) => {
                format!("{domain}:{port}")
                    .to_socket_addrs()
                    .map_err(|e| HostLookup.context(e))?
                    .next()
                    .ok_or_else(|| HostLookup.context("No socket addresses found for host"))?
            }
        };

        let http_settings = HttpSettings {
            hostname: url.host_str(),
            protocol: match url.scheme() {
                #[cfg(feature = "tls")]
                "https" => HttpProtocol::Https,
                _ => HttpProtocol::Http,
            },
            headers: headers.unwrap_or_default(),
        };

        Self::new(&address, timeout_settings, http_settings)
    }

    /// Send a HTTP GET request and return the response data as a buffer.
    pub fn get(&mut self, path: &str, headers: HttpHeaders) -> GDResult<Vec<u8>> { self.request("GET", path, headers) }

    /// Send a HTTP GET request and parse the JSON resonse.
    pub fn get_json<T: DeserializeOwned>(&mut self, path: &str, headers: HttpHeaders) -> GDResult<T> {
        self.request_json("GET", path, headers)
    }

    /// Send a HTTP Post request with JSON data and parse a JSON response.
    pub fn post_json<T: DeserializeOwned, S: Serialize>(
        &mut self,
        path: &str,
        headers: HttpHeaders,
        data: S,
    ) -> GDResult<T> {
        self.request_with_json_data("POST", path, headers, data)
    }

    /// Send a HTTP Post request with FORM data and parse a JSON response.
    pub fn post_json_with_form<T: DeserializeOwned>(
        &mut self,
        path: &str,
        headers: HttpHeaders,
        data: &[(&str, &str)],
    ) -> GDResult<T> {
        self.request_with_form_data("POST", path, headers, data)
    }

    // NOTE: More methods can be added here as required using the request_json or
    // request_with_json methods

    fn make_request(&self, method: &str, headers: HttpHeaders) -> Request {
        let mut request = self.client.request_url(method, &self.address);

        // Set the request headers.
        for (key, value) in self.headers.iter() {
            request = request.set(key, value);
        }

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.set(key, value);
            }
        }

        request
    }

    /// Internal request method, makes a request with an arbitrary HTTP method.
    #[inline]
    fn request(&mut self, method: &str, path: &str, headers: HttpHeaders) -> GDResult<Vec<u8>> {
        // Append the path to the pre-parsed URL and create a request object.
        self.address.set_path(path);
        let request = self.make_request(method, headers);

        // Send the request.
        let http_response = request.call().map_err(|e| PacketSend.context(e))?;

        read_body(http_response)
    }

    /// Send a HTTP request without any data and parse the JSON response.
    #[inline]
    fn request_json<T: DeserializeOwned>(&mut self, method: &str, path: &str, headers: HttpHeaders) -> GDResult<T> {
        // Append the path to the pre-parsed URL and create a request object.
        self.address.set_path(path);
        let request = self.make_request(method, headers);

        // Send the request and parse the response as JSON.
        read_json(request.call().map_err(|e| PacketSend.context(e))?)
    }

    /// Send a HTTP request with JSON data and parse the JSON response.
    #[inline]
    fn request_with_json_data<T: DeserializeOwned, S: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        headers: HttpHeaders,
        data: S,
    ) -> GDResult<T> {
        self.address.set_path(path);
        let request = self.make_request(method, headers);

        read_json(request.send_json(data).map_err(|e| PacketSend.context(e))?)
    }

    /// Send a HTTP request with FORM data and parse the JSON response.
    #[inline]
    fn request_with_form_data<T: DeserializeOwned>(
        &mut self,
        method: &str,
        path: &str,
        headers: HttpHeaders,
        data: &[(&str, &str)],
    ) -> GDResult<T> {
        self.address.set_path(path);
        let request = self.make_request(method, headers);

        read_json(request.send_form(data).map_err(|e| PacketSend.context(e))?)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};

    use super::*;

    #[test]
    fn http_settings_builder() {
        const HOSTNAME: &str = "example.org";

        #[cfg(feature = "tls")]
        const PROTOCOL: HttpProtocol = HttpProtocol::Https;
        #[cfg(not(feature = "tls"))]
        const PROTOCOL: HttpProtocol = HttpProtocol::Http;

        let settings = HttpSettings::default()
            .hostname(HOSTNAME)
            .protocol(PROTOCOL)
            .header("Gamedig", "Is Awesome")
            .headers(vec![("Foo", "bar")])
            .header("Baz", "Buzz");

        assert_eq!(settings.hostname, Some(HOSTNAME));
        assert_eq!(settings.protocol, PROTOCOL);
        assert_eq!(settings.headers, vec![("Foo", "bar"), ("Baz", "Buzz"),]);
    }

    /// The cap on HTTP bodies.
    const ONE_MIB: usize = 1024 * 1024;

    /// A loopback HTTP server answering one request with a `body_length`-byte
    /// body, with or without a Content-Length header.
    fn http_server(body_length: usize, content_length: bool) -> SocketAddr {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let header = if content_length {
                format!("HTTP/1.1 200 OK\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n")
            } else {
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = stream.write_all(header.as_bytes());
            // The client stops reading after the cap; ignore the broken pipe.
            let _ = stream.write_all(&vec![b'x'; body_length]);
        });
        address
    }

    /// HTTP bodies used to be read up to 1 GB and silently cut there.
    #[test]
    fn http_body_over_1_mib_is_an_overflow_error() {
        for content_length in [true, false] {
            let address = http_server(ONE_MIB + 1, content_length);
            let mut client = HttpClient::new(&address, &None, HttpSettings::<String>::default()).unwrap();

            let error = client.get("/", None).unwrap_err();
            assert_eq!(
                error.kind,
                crate::GDErrorKind::PacketOverflow,
                "content_length {content_length}"
            );
        }
    }

    #[test]
    fn http_body_up_to_1_mib_is_read() {
        let address = http_server(ONE_MIB, true);
        let mut client = HttpClient::new(&address, &None, HttpSettings::<String>::default()).unwrap();

        assert_eq!(client.get("/", None).unwrap().len(), ONE_MIB);
    }

    /// JSON requests go through the same cap.
    #[test]
    fn http_json_body_over_1_mib_is_an_overflow_error() {
        let address = http_server(ONE_MIB + 1, true);
        let mut client = HttpClient::new(&address, &None, HttpSettings::<String>::default()).unwrap();

        let error = client.get_json::<serde_json::Value>("/", None).unwrap_err();
        assert_eq!(error.kind, crate::GDErrorKind::PacketOverflow);
    }

    #[test]
    fn http_client_new() {
        const PROTOCOL: HttpProtocol = HttpProtocol::Http;

        const ADDRESS: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8000));

        let settings = HttpSettings {
            protocol: PROTOCOL,
            hostname: Some("github.com"),
            headers: vec![("Authorization", "UUDDLRLRBA")],
        };

        let client = HttpClient::new(&ADDRESS, &None, settings).unwrap();

        assert_eq!(client.address.as_str(), "http://github.com:8000/");
        assert_eq!(
            client.headers,
            vec![(String::from("Authorization"), String::from("UUDDLRLRBA")),]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    #[ignore = "HTTP requests won't work without internet"]
    fn https_json_get_request() {
        let address = "api.github.com:443"
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let settings = HttpSettings::default()
            .protocol(HttpProtocol::Https)
            .hostname("api.github.com");

        let mut client = HttpClient::new(&address, &None, settings).unwrap();

        let response: serde_json::Value = client.get_json("/events", None).unwrap();

        println!("{:?}", response);
    }

    #[test]
    #[ignore = "HTTP requests won't work without internet"]
    fn http_json_get_request() {
        let address = "postman-echo.com:80"
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let settings = HttpSettings::default().hostname("postman-echo.com");

        let mut client = HttpClient::new(&address, &None, settings).unwrap();

        let response: serde_json::Value = client.get_json("/get", None).unwrap();

        println!("{:?}", response);
    }

    #[test]
    #[ignore = "HTTP requests won't work without internet"]
    fn http_get_request() {
        let address = "ifconfig.me:80".to_socket_addrs().unwrap().next().unwrap();

        let settings = HttpSettings::default()
            .hostname("ifconfig.me")
            .header("User-Agent", "Curl/8.6.0");

        let mut client = HttpClient::new(&address, &None, settings).unwrap();

        let response = client.get("/", None).unwrap();

        println!("{:?}", std::str::from_utf8(&response));
    }

    #[test]
    #[ignore = "HTTP requests won't work without internet"]
    fn http_get_from_url() {
        let mut client = HttpClient::from_url("http://postman-echo.com/path-is-ignored", &None, None).unwrap();

        let response: serde_json::Value = client.get_json("/get", None).unwrap();

        println!("{:?}", response);
    }

    #[test]
    #[ignore = "HTTP requests won't work without internet"]
    fn http_get_from_url_parsed() {
        let url = Url::parse("http://postman-echo.com/path-is-ignored").unwrap();

        let mut client = HttpClient::from_url(url, &None, None).unwrap();

        let response: serde_json::Value = client.get_json("/get", None).unwrap();

        println!("{:?}", response);
    }
}
