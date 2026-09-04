//! A driver that follows discovered links depth first.

use std::collections::HashSet;

use super::{Capture, CaptureProcessor, Discovery, Driver, Inspection, Request};
use crate::Error;

/// A depth-first crawl of given requests, following the links a [`CaptureProcessor`] discovers.
///
/// The given requests are made in order, whether or not they repeat each other, and a capture's
/// discoveries are requested next, in the order the processor returns them, before anything
/// else waiting. A discovery that repeats a URL already given or discovered is skipped unless
/// deduplication is turned off.
pub struct Crawl<'a> {
    /// Waiting requests, the next one last.
    stack: Vec<Request>,
    /// The request whose outcome the session has not reported.
    current: Option<Request>,
    /// Every URL given or discovered, or `None` when discoveries are repeated.
    seen: Option<HashSet<String>>,
    processor: Option<Box<dyn CaptureProcessor + 'a>>,
}

impl<'a> Crawl<'a> {
    /// A crawl making `requests` in order, without a processor.
    pub fn new<I: IntoIterator<Item = Request>>(requests: I) -> Self {
        let mut stack = requests.into_iter().collect::<Vec<_>>();
        stack.reverse();
        let seen = stack.iter().map(|request| request.url.clone()).collect();

        Self {
            stack,
            current: None,
            seen: Some(seen),
            processor: None,
        }
    }

    /// A crawl requesting `urls` as seeds, in order, without a processor.
    pub fn seeds<I: IntoIterator<Item = S>, S: AsRef<str>>(urls: I) -> Self {
        Self::new(urls.into_iter().map(|url| Request::seed(url.as_ref())))
    }

    /// Set the processor called for every successful capture.
    #[must_use]
    pub fn processor<P: CaptureProcessor + 'a>(mut self, processor: P) -> Self {
        self.processor = Some(Box::new(processor));
        self
    }

    /// Skip a discovered URL that repeats one already given or discovered, or request it again
    /// when `dedupe` is false.
    ///
    /// Without deduplication, the processor is responsible for ending a crawl of pages that link
    /// to each other.
    #[must_use]
    pub fn dedupe_discoveries(mut self, dedupe: bool) -> Self {
        self.seen = dedupe.then(|| {
            self.stack
                .iter()
                .chain(&self.current)
                .map(|request| request.url.clone())
                .collect()
        });
        self
    }

    /// The requests still to make, in the order they would be made.
    ///
    /// A request the session was cancelled before completing comes first. A crawl resumes from
    /// these requests, in this order.
    pub fn unrequested(&self) -> impl Iterator<Item = &Request> {
        self.current.iter().chain(self.stack.iter().rev())
    }
}

impl Driver for Crawl<'_> {
    fn next(&mut self) -> Option<Request> {
        self.current = self.stack.pop();
        self.current.clone()
    }

    fn inspect(&mut self, capture: &Capture<'_>) -> Inspection {
        self.current = None;
        let Some(processor) = self.processor.as_mut() else {
            return Inspection::default();
        };
        let Discovery {
            mut links,
            title,
            error,
        } = processor.inspect(capture);
        if error.is_some() {
            return Inspection { title, error };
        }
        links.retain(|link| {
            self.seen
                .as_mut()
                .is_none_or(|seen| seen.insert(link.clone()))
        });
        // The stack is filled in reverse so that the first link is requested first.
        self.stack.extend(
            links
                .into_iter()
                .rev()
                .map(|url| Request::extra(url, capture.final_url)),
        );

        Inspection { title, error: None }
    }

    fn failed(&mut self, _url: &str, _error: &Error) {
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    /// Discover the same links from every capture.
    struct FixedLinks(Vec<&'static str>);

    impl CaptureProcessor for FixedLinks {
        fn inspect(&mut self, _capture: &Capture<'_>) -> Discovery {
            Discovery {
                links: self.0.iter().map(|link| (*link).to_owned()).collect(),
                ..Discovery::default()
            }
        }
    }

    fn capture<'a>(url: &'a str, final_url: &'a str) -> Capture<'a> {
        Capture::new(url, final_url, b"", RESPONSE).expect("a complete response")
    }

    #[test]
    fn requests_are_made_in_order_and_discoveries_come_first() {
        let mut crawl = Crawl::new([
            Request::extra("https://example.com/extra", "https://example.com/"),
            Request::seed("https://example.com/"),
            Request::seed("https://example.com/about"),
        ])
        .processor(FixedLinks(vec![
            "https://example.com/a",
            "https://example.com/b",
        ]));

        assert_eq!(
            crawl.next(),
            Some(Request::extra(
                "https://example.com/extra",
                "https://example.com/"
            ))
        );
        assert_eq!(
            crawl.inspect(&capture(
                "https://example.com/extra",
                "https://example.com/final"
            )),
            Inspection::default()
        );
        assert_eq!(
            crawl.unrequested().cloned().collect::<Vec<_>>(),
            [
                Request::extra("https://example.com/a", "https://example.com/final"),
                Request::extra("https://example.com/b", "https://example.com/final"),
                Request::seed("https://example.com/"),
                Request::seed("https://example.com/about"),
            ]
        );
    }

    #[test]
    fn repeated_discoveries_are_skipped_unless_deduplication_is_off() {
        let seeds = ["https://example.com/", "https://example.com/about"];
        let links = vec!["https://example.com/", "https://example.com/new"];
        let capture = capture("https://example.com/", "https://example.com/");

        let mut crawl = Crawl::seeds(seeds).processor(FixedLinks(links.clone()));
        crawl.next();
        crawl.inspect(&capture);
        assert_eq!(
            crawl
                .unrequested()
                .map(|request| request.url.as_str())
                .collect::<Vec<_>>(),
            ["https://example.com/new", "https://example.com/about"]
        );
        crawl.next();
        crawl.inspect(&capture);
        assert_eq!(
            crawl
                .unrequested()
                .map(|request| request.url.as_str())
                .collect::<Vec<_>>(),
            ["https://example.com/about"]
        );

        let mut crawl = Crawl::seeds(seeds)
            .processor(FixedLinks(links))
            .dedupe_discoveries(false);
        crawl.next();
        crawl.inspect(&capture);
        assert_eq!(
            crawl
                .unrequested()
                .map(|request| request.url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://example.com/",
                "https://example.com/new",
                "https://example.com/about"
            ]
        );
    }

    #[test]
    fn a_request_without_an_outcome_is_still_unrequested() {
        let mut crawl = Crawl::seeds(["https://example.com/", "https://example.com/about"]);

        crawl.next();
        assert_eq!(crawl.unrequested().count(), 2);

        crawl.failed("https://example.com/", &Error::MissingHost(String::new()));
        assert_eq!(crawl.unrequested().count(), 1);

        crawl.next();
        crawl.inspect(&capture(
            "https://example.com/about",
            "https://example.com/about",
        ));
        assert_eq!(crawl.unrequested().count(), 0);
        assert_eq!(crawl.next(), None);
    }

    #[test]
    fn a_processor_error_discards_its_links() {
        struct Failing;

        impl CaptureProcessor for Failing {
            fn inspect(&mut self, _capture: &Capture<'_>) -> Discovery {
                Discovery {
                    links: vec!["https://example.com/next".to_owned()],
                    title: Some("Title".to_owned()),
                    error: Some("cannot continue".to_owned()),
                }
            }
        }

        let mut crawl = Crawl::seeds(["https://example.com/"]).processor(Failing);
        crawl.next();

        assert_eq!(
            crawl.inspect(&capture("https://example.com/", "https://example.com/")),
            Inspection {
                title: Some("Title".to_owned()),
                error: Some("cannot continue".to_owned()),
            }
        );
        assert_eq!(crawl.unrequested().count(), 0);
    }
}
