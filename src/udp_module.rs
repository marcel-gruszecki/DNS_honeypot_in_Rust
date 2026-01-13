use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use sqlx::{Pool, Sqlite};
use tokio::net::UdpSocket;
use tokio::time::sleep;
use crate::{console_print, console_print_err, IP, PORT};
use crate::database::send_log;
use crate::dns::handle_request;

pub async fn udp_server(database: Arc<Pool<Sqlite>>) {
    let socket = udp_connect_to_socket().await;
    loop {
        let mut buffer: [u8; 1024] = [0; 1024];
        let (len, addr) = udp_socket_recv(socket.clone(), &mut buffer).await;

        let socket = socket.clone();
        let database = database.clone();
        let data = buffer[..len].to_vec();

        tokio::spawn(async move {
            let record = match handle_request(&data) {
                Ok(req) => { req }
                Err(err) => {
                    console_print_err(format!("UDP handle request error: {}.", err));
                    return
                }
            };


            let data = record.response_bytes.clone();

            match send_log(database.clone(), record, len, addr).await {
                Ok(_) => {}
                Err(err) => {
                    console_print_err(format!("Error in sending log to database(UDP): {}.", err));
                    return
                }
            }

            match socket.send_to(&data, addr).await {
                Ok(bytes) => {
                    console_print(format!("{} bytes sent to {} from UDP server.", bytes, addr));
                }
                Err(err) => {
                    console_print_err(format!("Error in sending response to user (UDP): {}.", err));
                    return
                }
            }
        });
    }
}

async fn udp_connect_to_socket() -> Arc<UdpSocket> {
    loop {
        match UdpSocket::bind(format!("{}:{}", IP, PORT)).await {
            Ok(soc) => {
                console_print(String::from("Connected to UDP socket."));
                break Arc::new(soc);
            },
            Err(err) => {
                console_print_err(format!("UDP socket connection error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to reconnect in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            },
        };
    }
}

async fn udp_socket_recv(socket: Arc<UdpSocket>, buffer: &mut [u8; 1024]) -> (usize, SocketAddr) {
    loop {
        match socket.recv_from(buffer).await {
            Ok(soc) => {
                break soc;
            },
            Err(err) => {
                console_print_err(format!("UDP socket receiving error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to reconnect in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            },
        };
    }
}