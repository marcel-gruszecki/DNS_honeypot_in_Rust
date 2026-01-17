mod database;
mod dns;
mod tcp_module;
mod udp_module;

use std::net::{Ipv4Addr};
use chrono::Local;
use crate::database::{connect_to_database, database_init, db_daily_refresh};
use crate::tcp_module::tcp_server;
use crate::udp_module::udp_server;

pub const IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
pub const PORT: u32 = 53;


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
