use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use chrono::Local;
use sqlx::{SqlitePool, Executor, Sqlite, Pool};
use sqlx::sqlite::SqliteConnectOptions;
use tokio::time;
use tokio::time::sleep;
use crate::{console_print, console_print_err, IP, PORT};
use crate::dns::Request;

const DAILY_REFRESH_TIME: Duration = Duration::new(3600, 00);
pub const DB_PATH: &str = "./dns_logs.sqlite";

pub async fn connect_to_database() -> Arc<Pool<Sqlite>> {
    loop {
        let db_options = SqliteConnectOptions::new()
            .filename(DB_PATH)
            .create_if_missing(true);

        match SqlitePool::connect_with(db_options).await {
            Ok(db) => {
                console_print(String::from("Connected to database."));
                break Arc::new(db);
            },
            Err(err) => {
                console_print_err(format!("Database connection error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to reconnect in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            },
        }
    }
}
pub async fn database_init(database_pool: Arc<SqlitePool>) {
    loop {
        match init(database_pool.clone()).await {
            Ok(_) => {
                console_print(String::from("Database has been initialized."));
                break
            }
            Err(err) => {
                console_print_err(format!("Database initialization error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to initialized in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            }
        };
    }
}
async fn init(db: Arc<SqlitePool>) -> Result<(), sqlx::Error> {
    db.execute(sqlx::query(
        "
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        day TEXT,
        question TEXT,
        question_length INTEGER,
        response TEXT,
        server_ip TEXT,
        server_port INTEGER,
        client_ip TEXT,
        client_port INTEGER,
        q_type TEXT
    )
        "
    )).await?;

    db.execute(sqlx::query(
        "
    CREATE TABLE IF NOT EXISTS daily_summary (
        day TEXT,
        total_events INTEGER,
        by_class TEXT,
        first_seen TEXT,
        last_seen TEXT,
        PRIMARY KEY (day, by_class)
    )
        "
    )).await?;

    Ok(())
}

pub async fn db_daily_refresh(db: Arc<SqlitePool>) {
    let mut interval = time::interval(DAILY_REFRESH_TIME);

    loop {
        interval.tick().await;

        match daily(db.clone()).await {
            Ok(_) => {console_print(String::from("Daily database has been refreshed."));}
            Err(err) => {
                console_print_err(format!("Database daily refresh error: {}", err));
                sleep(Duration::from_secs(1)).await;
                console_print(String::from("Trying to initialized in 5 sec."));
                sleep(Duration::from_secs(5)).await;
            }
        }
    }

}

async fn daily(db: Arc<SqlitePool>) -> Result<(), sqlx::Error> {
    db.execute(sqlx::query(
        "
        INSERT OR REPLACE INTO daily_summary (day, total_events, by_class, first_seen, last_seen)
        SELECT
            bf.day,
            COUNT(bf.Czas_Sekunda),
            'Brute Force',
            MIN(bf.Czas_Sekunda),
            MAX(bf.Czas_Sekunda)
        FROM (
            SELECT
                STRFTIME('%Y-%m-%d %H:%M:%S', timestamp) AS Czas_Sekunda,
                day,
                client_ip
            FROM
                logs
            GROUP BY
                Czas_Sekunda,
                client_ip
            HAVING
                COUNT(*) >= 20
        ) AS bf
        GROUP BY
            bf.day;
            "
    )).await?;

    Ok(())
}

pub async fn send_log(db: Arc<SqlitePool>, record: Request, len: usize, addr: SocketAddr) -> Result<(), sqlx::Error> {
    let timestamp = Local::now();

    db.execute(sqlx::query(
        "
    INSERT INTO logs (timestamp, day, question, question_length, response, server_ip, server_port, client_ip, client_port, q_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "
    )
        .bind(timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .bind(timestamp.format("%Y-%m-%d").to_string())
        .bind(record.response_text)
        .bind(len as i32)
        .bind(record.domain)
        .bind(IP.to_string())
        .bind(PORT)
        .bind(addr.ip().to_string())
        .bind(addr.port().to_string())
        .bind(record.response_type)
    ).await?;

    Ok(())
}