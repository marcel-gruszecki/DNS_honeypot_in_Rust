use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
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

const DAILY_REFRESH_TIME: Duration = Duration::new(10, 00);
pub const DB_PATH: &str = "/app/data/honeypot.db";

pub const FL_PATH: &str = "/app/data/forbidden_domains.txt";

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
        daily(db.clone(), FL_PATH).await;
    }
}

async fn daily(db: Arc<SqlitePool>, file_path: &str) {
    let mut forbidden_domains = Vec::new();

    let file_result = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path);

    match file_result {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(domain) = line {
                    let trimmed = domain.trim();
                    if !trimmed.is_empty() {
                        forbidden_domains.push(trimmed.to_string());
                    }
                }
            }
        }
        Err(e) => {
            console_print_err(format!("Error handling forbidden domains file ({}): {}", file_path, e));
        }
    };

    let forbidden_placeholders = if forbidden_domains.is_empty() {
        "'---empty-list---'".to_string()
    } else {
        forbidden_domains.iter().map(|_| "?").collect::<Vec<_>>().join(",")
    };

    let sql = format!(
        "
        INSERT OR REPLACE INTO daily_summary (day, total_events, by_class, first_seen, last_seen)

        -- 1. Flood Attack (Jeśli w jakiejkolwiek minucie było > 50 zapytań, zliczamy to jako 1 incydent Flood na dzień)
            SELECT day, 1, 'Flood Attack', MIN(timestamp), MAX(timestamp)
            FROM logs
            WHERE client_ip IN (
                SELECT client_ip
                FROM logs
                GROUP BY day, client_ip, STRFTIME('%Y-%m-%d %H:%M', timestamp)
                HAVING COUNT(*) >= 50
            )
            GROUP BY day

        UNION ALL

        -- 2. Zone Transfer
        SELECT day, COUNT(*), 'Zone Transfer', MIN(timestamp), MAX(timestamp)
        FROM logs WHERE q_type IN ('SOA') GROUP BY day

        UNION ALL

        -- 3. DNS Tunneling (Checking question length)
        SELECT day, COUNT(*), 'DNS Tunneling', MIN(timestamp), MAX(timestamp)
        FROM logs WHERE LENGTH(question) > 60 GROUP BY day

        UNION ALL

        -- 4. Amplification
        SELECT day, COUNT(*), 'Amplification Attempt', MIN(timestamp), MAX(timestamp)
        FROM logs WHERE q_type IN ('ANY', 'TXT') GROUP BY day

        UNION ALL

        -- 5. Forbidden Domains
        SELECT day, COUNT(*), 'Forbidden Domain', MIN(timestamp), MAX(timestamp)
        FROM logs WHERE question IN ({}) GROUP BY day;
        ",
        forbidden_placeholders
    );

    let mut query = sqlx::query(&sql);

    if !forbidden_domains.is_empty() {
        for domain in forbidden_domains {
            query = query.bind(domain);
        }
    }

    match db.execute(query).await {
        Ok(_) => console_print(String::from("Daily summary successfully updated in database.")),
        Err(e) => console_print_err(format!("SQL Error in daily summary: {}", e)),
    }

    // Cleaning logs older than 3 days (Changed from -7 to -3 as requested before)
    match db.execute(sqlx::query("DELETE FROM logs WHERE timestamp < DATETIME('now', '-3 days');")).await {
        Ok(result) => {
            let rows = result.rows_affected();
            if rows > 0 {
                console_print(format!("Cleanup: Removed {} old log entries (older than 3 days).", rows));
            }
        },
        Err(e) => {
            console_print_err(format!("SQL Error (Cleanup): {}", e));
        }
    }
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