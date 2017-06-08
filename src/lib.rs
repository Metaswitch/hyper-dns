
extern crate futures;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate trust_dns;

use trust_dns::client::ClientHandle;
use rand::Rng;
use hyper::net::{NetworkConnector, NetworkStream};

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C: NetworkConnector> {
    connector: C,
    dns_addr: std::net::SocketAddr,
}

impl<C: NetworkConnector> DnsConnector<C> {
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {

        DnsConnector {
            connector: connector,
            dns_addr: dns_addr,
        }
    }
}

impl<C: NetworkConnector<Stream = S>, S: NetworkStream + Send> NetworkConnector
    for DnsConnector<C> {
    type Stream = S;

    /// Performs DNS SRV resolution, then calls into the inner connector with the results.
    /// Note that currently this does not take into account the following in the SRV record:
    /// * weight
    /// * priority
    /// It just takes a random entry in the DNS answers that are returned.
    fn connect(&self, host: &str, _port: u16, scheme: &str) -> hyper::Result<S> {

        let mut io =
            tokio_core::reactor::Core::new().expect("Failed to create event loop for DNS query");
        let (stream, sender) = trust_dns::udp::UdpClientStream::new(self.dns_addr, io.handle());
        let mut dns_client =
            trust_dns::client::ClientFuture::new(stream, sender, io.handle(), None);

        // TODO: Check if this is a domain name or not before trying to use
        // DNS resolution.

        // Add a `.` to the end of the host so that we can query the domain records.
        let name = trust_dns::rr::Name::parse(&format!("{}.", host), None).unwrap();

        match io.run(dns_client.query(name,
                                      trust_dns::rr::DNSClass::IN,
                                      trust_dns::rr::RecordType::SRV)) {
            Ok(res) => {
                let answers = res.get_answers();

                if answers.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                   "No valid DNS answers")
                                       .into());
                }

                let mut rng = rand::thread_rng();
                let answer = rng.choose(answers)
                    .expect("Sort out what to return here");

                let srv = match *answer.get_rdata() {
                    trust_dns::rr::RData::SRV(ref srv) => srv,
                    _ => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                       "Unexpected DNS response")
                                           .into())
                    }
                };

                let target = srv.get_target();

                // Now need to lookup the target in the additional information
                let additionals = res.get_additionals();

                let entry = additionals
                    .iter()
                    .find(|additional| additional.get_name() == target);

                if let Some(entry) = entry {
                    let addr = match *entry.get_rdata() {
                        trust_dns::rr::RData::A(ref addr) => addr,
                        _ => {
                            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                           "Did not receive a valid record")
                                               .into())
                        }
                    };

                    self.connector
                        .connect(&addr.to_string(), srv.get_port(), scheme)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other,
                                            "Did not receive a valid record")
                                .into())
                }

            }
            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to query DNS server")
                        .into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}