//! DNS resolver for Hyper

#[macro_use]
extern crate log;
extern crate futures;
extern crate hyper;
extern crate rand;
extern crate trust_dns;

use std::io;
use std::time::Duration;

use futures::future;
use hyper::client::connect::{Connect, Destination};
use hyper::rt::Future;
use rand::Rng;
use trust_dns::client::ClientHandle;

/// What flavour of DNS resolution to use.
#[derive(Debug, Clone)]
pub enum RecordType {
    /// A records
    A,
    /// SRV records
    SRV,
    /// Automatic (i.e. A records if a port is provided, SRV otherwise)
    AUTO,
}

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C>
where
    C: Connect,
{
    /// The DNS server address
    dns_addr: std::net::SocketAddr,

    /// The inner connector object
    connector: C,

    /// DNS record type to look up
    record_type: RecordType,

    /// Whether to only allow the connector (after DNS resolution) to yield an HTTPS destination
    force_https: bool,
}

impl<C> DnsConnector<C>
where
    C: Connect,
{
    /// Create a new `DnsConnector` instance with AUTO DNS record type.
    pub fn new(dns_addr: std::net::SocketAddr, connector: C, force_https: bool) -> DnsConnector<C> {
        Self::new_with_resolve_type(dns_addr, connector, RecordType::AUTO, force_https)
    }

    /// Create a new `DnsConnector` instance with specified DNS record type.
    pub fn new_with_resolve_type(
        dns_addr: std::net::SocketAddr,
        connector: C,
        record_type: RecordType,
        force_https: bool,
    ) -> DnsConnector<C> {
        DnsConnector {
            dns_addr,
            connector,
            record_type,
            force_https,
        }
    }
}

impl<C> Connect for DnsConnector<C>
where
    C: 'static + Clone + Connect<Error = io::Error>,
    C::Transport: Send + 'static,
    C::Future: Send + 'static,
{
    type Transport = C::Transport;
    type Error = io::Error;
    type Future = Box<
        dyn Future<Item = <C::Future as Future>::Item, Error = <C::Future as Future>::Error> + Send,
    >;

    /// Implementation of the main Connect trait function.
    fn connect(&self, dst: Destination) -> Self::Future {
        let connector = self.connector.clone();
        let force_https = self.force_https;

        debug!("Trying to resolve {:?}", dst);

        // We would expect a DNS request to be responded to quickly, but add a timeout
        // to ensure that we don't wait for ever if the DNS server does not respond.
        let timeout = Duration::from_millis(30000);

        let (stream, sender) =
            trust_dns::tcp::TcpClientStream::with_timeout(self.dns_addr, timeout);

        let dns_client = trust_dns::client::ClientFuture::new(stream, sender, None);

        // Check if this is a domain name or not before trying to use DNS resolution.
        match dst.host().to_string().parse() {
            Ok(std::net::Ipv4Addr { .. }) => {
                // Nothing to do, so just pass it along to the main connector
                Box::new(connector.connect(dst.clone()))
            }
            Err(_) => {
                let port = dst.port();
                let scheme = dst.scheme().to_string();
                let host = dst.host().to_string();

                debug!("Trying to resolve {}://{}", scheme, &host);

                // Add a `.` to the end of the host so that we can query the domain records.
                let name = trust_dns::rr::Name::parse(&format!("{}.", host), None).unwrap();

                let trust_record_type = match self.record_type {
                    RecordType::A => trust_dns::rr::RecordType::A,
                    RecordType::SRV => trust_dns::rr::RecordType::SRV,
                    RecordType::AUTO => {
                        // If the port is not provided, then and perform SRV lookup, otherwise lookup
                        // A records.
                        if port.is_none() {
                            trust_dns::rr::RecordType::SRV
                        } else {
                            debug!("Using A record lookup for: {}", &host);
                            trust_dns::rr::RecordType::A
                        }
                    }
                };

                debug!("Sending DNS request");

                let name_clone = name.clone();

                let future = dns_client
                    .and_then(move |mut client| {
                        // Send the request
                        client.query(
                            name_clone.clone(),
                            trust_dns::rr::DNSClass::IN,
                            trust_record_type,
                        )
                    })
                    .or_else(|e| {
                        // Handle errors
                        debug!("Received resolution error: {:?}", e);
                        future::err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to query DNS server",
                        ))
                    })
                    .and_then(move |res| {
                        // Handle response, initially by picking out the relevant record
                        debug!("Got resolution responses: {:?}", res);

                        let answers = res.answers();

                        if answers.is_empty() {
                            debug!("No valid answers received");
                            return future::err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "No valid DNS answers",
                            ));
                        }

                        // Create an random number generator used for various look-ups.
                        let mut rng = rand::thread_rng();

                        // Work out the relevant target, which may be within SRV records.
                        let (target, a_records, new_port) =
                            if let trust_dns::rr::RecordType::SRV = trust_record_type {
                                // Randomize the choice between entries, in case there are many and
                                // one is down.
                                let answer = match rng.choose(answers) {
                                    Some(entry) => entry,
                                    None => {
                                        return future::err(std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "Unable to choose from DNS answers",
                                        ));
                                    }
                                };

                                let srv = match *answer.rdata() {
                                    trust_dns::rr::RData::SRV(ref srv) => srv,
                                    _ => {
                                        return future::err(std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "Unexpected DNS response",
                                        ))
                                    }
                                };

                                (srv.target().clone(), res.additionals(), Some(srv.port()))
                            } else {
                                // For A record requests it is the domain name that
                                // we want to use.
                                (name.clone(), answers, port)
                            };

                        // Again, randomize the selection.
                        let entries: Vec<_> = a_records
                            .iter()
                            .filter(|record| record.name() == &target)
                            .collect();
                        let entry = rng.choose(&entries);

                        if let Some(entry) = entry {
                            let addr = match *entry.rdata() {
                                trust_dns::rr::RData::A(ref addr) => addr,
                                _ => {
                                    return future::err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "Did not receive a valid record",
                                    ))
                                }
                            };

                            future::ok((addr.to_string(), new_port))
                        } else {
                            future::err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Did not receive a valid record",
                            ))
                        }
                    })
                    .and_then(move |(ip, port)| {
                        // Actually update the destination with the IP (and port, if appropriate).
                        if let Some(port) = port {
                            debug!("Resolved request to {}://{}:{}", scheme, &ip, port);
                        } else {
                            debug!("Resolved request to {}://{}", scheme, &ip);
                        }

                        let mut new_dst = dst.clone();
                        new_dst.set_host(&ip).expect("Failed to set host");

                        if force_https {
                            new_dst
                                .set_scheme("https")
                                .expect("Failed to set scheme to HTTPS");
                        }

                        if let Some(port) = port {
                            new_dst.set_port(port);
                        }
                        connector.connect(new_dst)
                    });

                Box::new(future)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
