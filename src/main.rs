/*
Zapytania dla ANY:
Zapytania dla reszty: dig @127.0.0.1 -p 8080 google.com

Do zrobienia:
- Dodać ograniczenie do 10 000 000 logow.
- Dodać klase atakow gdy sa zapytania TXT i ANY.
- Dodać klase atakow gdy sa zapytania do zablokowanej listy.
 */
mod database;
mod dns;
mod tcp_module;
mod udp_module;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use chrono::Local;
use sqlx::{Pool, Sqlite};
use hickory_server::{ServerFuture};
use std::net::IpAddr;
use crate::database::{connect_to_database, database_init, db_daily_refresh, send_log, DB_PATH};
use crate::dns::{handle_request};
use crate::tcp_module::tcp_server;
use crate::udp_module::udp_server;

pub const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const PORT: u32 = 8080;

#[tokio::main]
async fn main() {
    let db_pool = connect_to_database().await;

    let database = db_pool.clone();

    database_init(database.clone()).await;

    tokio::spawn(db_daily_refresh(database.clone()));

    tokio::spawn(tcp_server(database.clone()));

    match tokio::spawn(udp_server(database.clone())).await {
        Ok(_) => {console_print(String::from("UDP server closed."))}
        Err(err) => {console_print_err(format!("UDP server error: {}", err))}
    };

}
pub fn console_print(s: String) {
    println!("{}: {}", Local::now().format("%H:%M:%S"), s);
}

pub fn console_print_err(s: String) {
    eprintln!("{}: {}", Local::now().format("%H:%M:%S"), s);
}
