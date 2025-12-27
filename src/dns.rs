use std::net::{Ipv4Addr, Ipv6Addr};
use hickory_server::proto::op::{Message, MessageType, Query};
use hickory_server::proto::ProtoError;
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::proto::rr::rdata::{HINFO, MX, NS, NULL, TXT};
use hickory_server::proto::serialize::binary::{BinEncodable, BinEncoder};
use rand::prelude::*;

#[derive(Clone)]
pub struct Request {
    pub domain: String,
    pub response_type: String,
    pub response_text: String,
    pub response_bytes: Vec<u8>,
}

impl Request {
    fn new() -> Self {
        Request {
            domain: String::new(),
            response_type: String::new(),
            response_text: String::new(),
            response_bytes: vec![],
        }
    }
}
pub fn handle_request(data: &Vec<u8>) -> Result<Request, ProtoError> {
    let query = Message::from_vec(data)?;

    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);

    let mut request = Request::new();

    if let Some(query) = query.queries().first() {
        response.add_query(query.clone());
        let record = build_record(query);

        request.response_type = record.record_type().to_string();
        request.response_text = record.name().to_string();
        request.domain = record.data().to_string();

        response.add_answer(record);
    }

    let mut buffer: Vec<u8> = vec![];

    let mut encoder = BinEncoder::new(&mut buffer);

    response.emit(&mut encoder)?;

    request.response_bytes = buffer;

    Ok(request)
}

pub fn build_record(query: &Query) -> Record {
    let name = query.name().clone();
    let record_type = query.query_type();
    let ttl = 3600;

    match record_type {
        RecordType::A => {
            let generated_ip = ipv4_generator(name.to_string());
            Record::from_rdata(name, ttl, RData::A(generated_ip.into()))
        },

        RecordType::AAAA => {
            let generated_ipv6 = ipv6_generator(name.to_string());
            Record::from_rdata(name, ttl, RData::AAAA(generated_ipv6.into()))
        },

        RecordType::MX => {
            let mail_name = Name::from_ascii("mail.gmail.com").unwrap();
            let mx_record = MX::new(10, mail_name);
            Record::from_rdata(name, ttl, RData::MX(mx_record))
        },

        RecordType::NS => {
            let ns_name = Name::from_ascii("ns1").unwrap();
            Record::from_rdata(name, ttl, RData::NS(NS(ns_name)))
        },

        RecordType::ANY => {
            let os_name = String::from("Windows");
            let cpu_name = String::from("Intel Core i5-14600KF");

            Record::from_rdata(name, ttl, RData::HINFO(HINFO::new(os_name, cpu_name)))
        },

        RecordType::TXT => {
            let txt_name = String::from("TXT_respone");
            (Record::from_rdata(name, ttl, RData::TXT(TXT::new(vec![txt_name]))))
        },
        _ => {
            let txt_name = String::from("Unknown type.");
            Record::from_rdata(name, ttl, RData::TXT(TXT::new(vec![txt_name])))
        },
    }
}

fn ipv4_generator(domain: String) -> Ipv4Addr {
    let mut seed: [u8; 32] = [0; 32];

    for i in domain.bytes().enumerate() {
        if i.0 > 31 { break;}
        seed[i.0] = i.1;
    }

    let mut rng = StdRng::from_seed(seed);

    let ip: [u8; 4] = rng.random();

    Ipv4Addr::from(ip)
}

fn ipv6_generator(domain: String) -> Ipv6Addr {
    let mut seed: [u8; 32] = [0; 32];

    for i in domain.bytes().enumerate() {
        if i.1 > 31 { break;}
        seed[i.0] = i.1;
    }

    let mut rng = StdRng::from_seed(seed);

    let ip: [u8; 16] = rng.random();

    Ipv6Addr::from(ip)
}