//! SOCKS5 CONNECT negotiation (RFC 1928), with RFC 1929 username/password authentication.
//! Negotiation uses the recorder's timed transport and is never included in captured HTTP bytes.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};

use crate::ConfigError;

#[derive(Clone)]
pub(super) struct Proxy {
    pub host: String,
    pub port: u16,
    remote_dns: bool,
    credentials: Option<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("remote_dns", &self.remote_dns)
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

impl Proxy {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let invalid = ConfigError::InvalidProxy;
        let url = url::Url::parse(value).map_err(|_| invalid("malformed URI"))?;
        let remote_dns = match url.scheme() {
            "socks5" => false,
            "socks5h" => true,
            _ => return Err(invalid("expected socks5:// or socks5h://")),
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid("paths, queries, and fragments are not supported"));
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| invalid("missing host"))?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(1080);
        if port == 0 {
            return Err(invalid("port must be nonzero"));
        }
        let uri = fluent_uri::Uri::parse(url.as_str()).map_err(|_| invalid("malformed URI"))?;
        let credentials = uri
            .authority()
            .and_then(|authority| authority.userinfo())
            .map(|userinfo| {
                let (user, password) = userinfo
                    .split_once(':')
                    .ok_or_else(|| invalid("authentication requires a username and password"))?;
                let user = user.decode().to_bytes().into_owned();
                let password = password.decode().to_bytes().into_owned();
                if !(1..=255).contains(&user.len()) || !(1..=255).contains(&password.len()) {
                    return Err(invalid(
                        "username and password must each contain 1 to 255 bytes",
                    ));
                }
                Ok((user, password))
            })
            .transpose()?;
        Ok(Self {
            host,
            port,
            remote_dns,
            credentials,
        })
    }

    pub fn tunnel(
        &self,
        stream: &mut (impl Read + Write),
        host: &str,
        port: u16,
    ) -> std::io::Result<()> {
        // Resolve locally only when requested, never as a fallback for remote DNS.
        let address = match host.parse::<IpAddr>() {
            Ok(address) => Some(address),
            Err(_) if self.remote_dns => None,
            Err(_) => Some(
                (host, port)
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            ErrorKind::NotFound,
                            "the host resolved to no addresses",
                        )
                    })?
                    .ip(),
            ),
        };
        let mut request = vec![5, 1, 0];
        match address {
            Some(IpAddr::V4(address)) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            Some(IpAddr::V6(address)) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
            None => {
                let length = u8::try_from(host.len()).map_err(|_| {
                    std::io::Error::new(ErrorKind::InvalidInput, "SOCKS hostname exceeds 255 bytes")
                })?;
                request.extend_from_slice(&[3, length]);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());

        let method = if self.credentials.is_some() { 2 } else { 0 };
        stream.write_all(&[5, 1, method])?;
        let mut selection = [0; 2];
        stream.read_exact(&mut selection)?;
        if selection != [5, method] {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "SOCKS authentication method rejected",
            ));
        }
        if let Some((user, password)) = &self.credentials {
            // Both lengths were checked when parsing the proxy configuration.
            let mut auth = vec![
                1,
                u8::try_from(user.len()).expect("validated username length"),
            ];
            auth.extend_from_slice(user);
            auth.push(u8::try_from(password.len()).expect("validated password length"));
            auth.extend_from_slice(password);
            stream.write_all(&auth)?;
            stream.read_exact(&mut selection)?;
            if selection != [1, 0] {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "SOCKS authentication failed",
                ));
            }
        }
        stream.write_all(&request)?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply)?;
        if reply[0] != 5 || reply[2] != 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "invalid SOCKS reply",
            ));
        }
        if reply[1] != 0 {
            return Err(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                format!("SOCKS CONNECT failed (status {})", reply[1]),
            ));
        }
        // BND.ADDR identifies the proxy's bound socket, not the origin. Consume it without
        // recording it as WARC-IP-Address. Domain replies need not be valid UTF-8.
        let length = match reply[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0];
                stream.read_exact(&mut length)?;
                usize::from(length[0])
            }
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid SOCKS address type",
                ));
            }
        };
        let mut bound = [0; 257];
        stream.read_exact(&mut bound[..length + 2])
    }
}

#[cfg(test)]
mod tests {
    use super::Proxy;

    #[test]
    fn configuration_rejects_unusable_proxies_without_exposing_credentials() {
        for uri in [
            "http://localhost:1080",
            "socks4://localhost:1080",
            "socks5h://",
            "socks5h://localhost:invalid",
            "socks5h://localhost:65536",
            "socks5h://localhost:0",
            "socks5h://localhost/path",
            "socks5h://localhost?query",
            "socks5h://localhost#fragment",
            "socks5h://secret@localhost",
            "socks5h://secret:@localhost",
            "socks5h://:secret@localhost",
            "socks5h://secret:%gg@localhost",
        ] {
            let error = Proxy::parse(uri).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        let oversized = format!("socks5h://{}:secret@localhost", "x".repeat(256));
        assert!(Proxy::parse(&oversized).is_err());
    }

    #[test]
    fn proxy_defaults_and_encoded_credentials_are_preserved() {
        let proxy = Proxy::parse("socks5h://user%40name:pass%3Aword@[::1]").unwrap();
        assert_eq!(proxy.host, "::1");
        assert_eq!(proxy.port, 1080);
        assert!(proxy.remote_dns);
        assert_eq!(
            proxy.credentials,
            Some((b"user@name".to_vec(), b"pass:word".to_vec()))
        );
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("user@name"));
        assert!(!debug.contains("pass:word"));
        assert!(!Proxy::parse("socks5://localhost:9050").unwrap().remote_dns);
    }

    struct Handshake {
        reply: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl std::io::Read for Handshake {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(bytes)
        }
    }

    impl std::io::Write for Handshake {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn only_a_complete_successful_reply_opens_the_tunnel() {
        use std::io::Read;

        let proxy = Proxy::parse("socks5h://localhost").unwrap();
        for (reply, succeeds) in [
            (vec![5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80], true),
            (vec![5, 0, 5, 0, 0, 3, 3, b'f', b'o', b'o', 0, 80], true),
            ([vec![5, 0, 5, 0, 0, 4], vec![0; 18]].concat(), true),
            (vec![5, 0, 5, 5, 0, 1], false),
            (vec![5, 0, 4, 0, 0, 1], false),
            (vec![5, 0, 5, 0, 1, 1], false),
            (vec![5, 0, 5, 0, 0, 9], false),
            (vec![5, 0, 5, 0, 0, 1], false),
            (vec![5, 2], false),
            (vec![4, 0], false),
        ] {
            let mut stream = Handshake {
                reply: std::io::Cursor::new(reply),
                sent: Vec::new(),
            };
            assert_eq!(
                proxy.tunnel(&mut stream, "origin.invalid", 80).is_ok(),
                succeeds
            );
            if succeeds {
                let mut remaining = Vec::new();
                stream.read_to_end(&mut remaining).unwrap();
                assert!(remaining.is_empty());
                assert_eq!(
                    stream.sent,
                    b"\x05\x01\x00\x05\x01\x00\x03\x0eorigin.invalid\x00\x50"
                );
            }
        }
        let mut stream = Handshake {
            reply: std::io::Cursor::new(vec![5, 2, 1, 1]),
            sent: Vec::new(),
        };
        let proxy = Proxy::parse("socks5h://user:pass@localhost").unwrap();
        assert_eq!(
            proxy
                .tunnel(&mut stream, "origin.invalid", 80)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
