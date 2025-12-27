use std::net::{SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use sqlx::{Pool, Sqlite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use crate::{console_print, console_print_err, IP, PORT};
use crate::database::send_log;
use crate::dns::handle_request;

pub async fn tcp_server(database: Arc<Pool<Sqlite>>) {
    let socket = tcp_listener_connect().await;

    loop {
        let (mut stream, addr) = tcp_socket_recv(socket.clone()).await;

        let database = database.clone();

        tokio::spawn(async move {

            loop {
                let mut len_bytes: [u8; 2] = [0; 2];

                if let Err(err) = stream.read_exact(&mut len_bytes).await {
                    if err.kind() != std::io::ErrorKind::UnexpectedEof {
                        console_print_err(format!("TCP read_exact (len) error with {}: {}", addr, err));
                    }
                    break;
                }

                let msg_len = u16::from_be_bytes(len_bytes) as usize;

                if msg_len == 0 || msg_len > 4096 {
                    console_print_err(format!("Invalid TCP packet length received from {}: {}", addr, msg_len));
                    break;
                }

                let mut data_vec = vec![0u8; msg_len];
                if let Err(err) = stream.read_exact(&mut data_vec).await {
                    console_print_err(format!("TCP read_exact (data) error with {}: {}", addr, err));
                    break;
                }

                let record = match handle_request(&data_vec) {
                    Ok(req) => { req }
                    Err(err) => {
                        console_print_err(format!("TCP handle request error: {}.", err));
                        continue;
                    }
                };

                match send_log(database.clone(), record.clone(), msg_len, addr).await {
                    Ok(_) => {}
                    Err(err) => {
                        console_print_err(format!("Error in sending log to database(TCP): {}.", err));
                    }
                }

                let response_bytes = record.response_bytes.clone();
                let response_len = response_bytes.len() as u16;

                if let Err(err) = stream.write_all(&response_len.to_be_bytes()).await {
                    console_print_err(format!("Error sending response length (TCP) to {}: {}", addr, err));
                    break;
                }

                match stream.write_all(&response_bytes).await {
                    Ok(_) => {
                        console_print(format!("Sent {} bytes response ({} data) to {} (TCP).", response_bytes.len() + 2, response_bytes.len(), addr));
                    }
                    Err(err) => {
                        console_print_err(format!("Error sending response data (TCP) to {}: {}", addr, err));
                        break;
                    }
                }
            }

            console_print(format!("Closing TCP connection with {}", addr));
        });
    }
}

async fn tcp_listener_connect() -> Arc<TcpListener> {
    loop {
        match TcpListener::bind(format!("{}:{}", IP, PORT)).await {
            Ok(soc) => {
                console_print(String::from("Connected to TCP socket."));
                break Arc::new(soc);
            },
            Err(err) => {
                console_print_err(format!("TCP socket connection error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to reconnect TCP socket in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            },
        };
    }
}

async fn tcp_socket_recv(tcp_socket: Arc<TcpListener>) -> (TcpStream, SocketAddr) {
    loop {
        match tcp_socket.accept().await {
            Ok(soc) => {
                break soc;
            },
            Err(err) => {
                console_print_err(format!("TCP socket receiving error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to reconnect in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            },
        };
    }
}


