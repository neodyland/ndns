use fxhash::FxHashSet;
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::{
    op::{Edns, Header, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, IntoName, Name, Record, RecordType},
    xfer::DnsResponse,
};
use hickory_server::{
    authority::{MessageResponse, MessageResponseBuilder},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
pub struct DnsHandler {
    upstream: Arc<Mutex<Client>>,
    cached_allow: Arc<RwLock<FxHashSet<String>>>,
    cached_block: Arc<RwLock<FxHashSet<String>>>,
    blocklist: FxHashSet<String>,
}

impl DnsHandler {
    const OLD_VERSION: u8 = 0;
    pub fn new(upstream: Arc<Mutex<Client>>, blocklist: FxHashSet<String>) -> Self {
        Self {
            upstream,
            cached_allow: Arc::new(RwLock::new(FxHashSet::default())),
            cached_block: Arc::new(RwLock::new(FxHashSet::default())),
            blocklist,
        }
    }
    fn does_end(name: &str, it: &str) -> bool {
        if !name.ends_with(it) {
            return false;
        }
        if name.chars().take(name.len() - it.len()).last() == Some('.') {
            return true;
        }
        false
    }
    async fn is_blocked(&self, name: &str) -> bool {
        if self.cached_block.read().await.contains(name) {
            return true;
        }

        if self.cached_allow.read().await.contains(name) {
            return false;
        }

        for it in &self.blocklist {
            if Self::does_end(name, it) {
                if self.cached_block.write().await.insert(name.to_string()) {
                    log::info!("Add {} to cached blocklist", name);
                }
                return true;
            }
        }

        self.cached_allow.write().await.insert(name.to_string());
        false
    }
    async fn forward_to_upstream(
        &self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> anyhow::Result<DnsResponse> {
        let mut upstream = { self.upstream.lock().await.clone() };
        let response = upstream.query(name, query_class, query_type).await?;
        Ok(response)
    }

    async fn handle_query<R: ResponseHandler>(
        &self,
        response_edns: Option<Edns>,
        request: &Request,
        response_handle: R,
    ) -> anyhow::Result<ResponseInfo> {
        let request_info = request.request_info()?;

        let name = request_info.query.name().into_name()?;
        let class = request_info.query.query_class();
        let qtype = request_info.query.query_type();
        let name_utf8 = name.to_utf8();

        let upstream_response = if self.is_blocked(&name_utf8).await {
            log::trace!("Blocked {name_utf8}");
            None
        } else {
            log::trace!("Resolving {name_utf8}");
            Some(self.forward_to_upstream(name.clone(), class, qtype).await?)
        };

        let response_builder = MessageResponseBuilder::from_message_request(request);

        match upstream_response {
            Some(response) => {
                let mut response_header = Header::response_from_request(request.header());
                response_header.set_recursion_available(response.recursion_available());
                response_header.set_response_code(response.response_code());

                Self::send_response(
                    response_edns,
                    response_builder.build(
                        response_header,
                        response.answers(),
                        response.authorities(),
                        &[],
                        response.additionals(),
                    ),
                    response_handle,
                )
                .await
            }
            None => {
                Self::send_response(
                    response_edns,
                    response_builder.error_msg(request.header(), ResponseCode::NXDomain),
                    response_handle,
                )
                .await
            }
        }
    }

    async fn send_response<'a, R: ResponseHandler>(
        response_edns: Option<Edns>,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
        mut response_handle: R,
    ) -> anyhow::Result<ResponseInfo> {
        if let Some(resp_edns) = response_edns {
            response.set_edns(resp_edns);
        }

        Ok(response_handle.send_response(response).await?)
    }
    async fn try_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> anyhow::Result<ResponseInfo> {
        request.request_info()?;
        let response_edns = match request.edns() {
            Some(req_edns) => {
                let mut response = MessageResponseBuilder::from_message_request(request);
                let mut response_header = Header::response_from_request(request.header());

                let mut resp_edns = Edns::new();
                resp_edns.set_dnssec_ok(true);
                resp_edns.set_max_payload(req_edns.max_payload().max(512));
                resp_edns.set_version(Self::OLD_VERSION);

                if req_edns.version() > Self::OLD_VERSION {
                    response_header.set_response_code(ResponseCode::BADVERS);
                    resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                    response.edns(resp_edns);

                    return Ok(response_handle
                        .send_response(response.build_no_records(response_header))
                        .await?);
                }
                Some(resp_edns)
            }
            None => None,
        };

        match request.message_type() {
            MessageType::Query if request.op_code() == OpCode::Query => {
                self.handle_query(response_edns, request, response_handle)
                    .await
            }
            _ => {
                let response = MessageResponseBuilder::from_message_request(request);
                Self::send_response(
                    response_edns,
                    response.error_msg(request.header(), ResponseCode::NotImp),
                    response_handle,
                )
                .await
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        Self::try_handle_request(self, request, response_handle)
            .await
            .unwrap_or_else(|e| {
                log::warn!("Error handling request: {e}");
                let mut header = Header::new(0, MessageType::Query, OpCode::Query);
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            })
    }
}
