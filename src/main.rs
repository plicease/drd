use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};
use sqlx::{PgPool, postgres::PgQueryResult};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::SystemTime;

/*

TODO:
 * change created to updated
 * change number to first4, and make it exectly four bytes

THEN:
 * recurse
 * better CLI

DROP TABLE file_record;
CREATE TABLE file_record (
    id SERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    directory TEXT NOT NULL,
    filename TEXT NOT NULL,
    number BIGINT DEFAULT NULL,
    size BIGINT NOT NULL,
    created TIMESTAMPTZ NOT NULL,
    sha1 CHAR(40) NOT NULL,
    UNIQUE (filename,directory,hostname)
);

*/

#[derive(Debug)]
struct FileRecord {
    directory: String,
    filename: String,
    hostname: String,
    number: u32, // first 4 bytes of the file
    size: u64,
    created: DateTime<Utc>,
    sha1: Option<String>, // optional checksum
}

impl FileRecord {
    fn from_path<P: AsRef<Path>>(path: P, with_sha1: bool) -> io::Result<Self> {
        let path = path.as_ref();

        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?
            .to_string();

        let directory = path
            .parent()
            .expect("x")
            .canonicalize()
            .expect("y")
            .display()
            .to_string();

        let hostname = hostname::get()
            .expect("unable to find hostname")
            .to_string_lossy()
            .into_owned();

        let metadata = std::fs::metadata(path)?;
        let size = metadata.len();

        let created_sys: SystemTime = match metadata.created() {
            Ok(t) => t,
            Err(_) => metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        };
        let created: DateTime<Utc> = created_sys.into();

        let mut file = File::open(path)?;

        // --- Read first 4 bytes as u32 ---
        let mut first4 = [0u8; 4];
        let mut read_bytes = 0;
        while read_bytes < 4 {
            let n = file.read(&mut first4[read_bytes..])?;
            if n == 0 {
                break; // file smaller than 4 bytes
            }
            read_bytes += n;
        }
        let number = if read_bytes == 4 {
            u32::from_le_bytes(first4) // interpret little endian
        } else {
            0 // fallback if file is smaller
        };

        // --- Optionally compute SHA1 ---
        let sha1 = if with_sha1 {
            // Rewind file for hashing
            let mut file = File::open(path)?;
            let mut hasher = Sha1::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        Ok(Self {
            directory,
            filename,
            hostname,
            number,
            size,
            created,
            sha1,
        })
    }

    async fn upsert(&self, pool: &PgPool) -> Result<PgQueryResult, sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO file_record (hostname, directory, filename, number, size, created, sha1)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (filename, directory, hostname)
            DO UPDATE SET
                number = EXCLUDED.number,
                size = EXCLUDED.size,
                created = EXCLUDED.created,
                sha1 = EXCLUDED.sha1
            "#,
            self.hostname,
            self.directory,
            self.filename,
            self.number as i32,
            self.size as i64,
            self.created,
            self.sha1,
        )
        .execute(pool)
        .await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .expect("please provide a path to a file (e.g., ./some/dir/file.bin)");

    let database_url = env::var("DATABASE_URL")
        .expect("please set DATABASE_URL, e.g. postgres://user:pass@localhost/dbname");
    let pool = PgPool::connect(&database_url).await?;

    let record = FileRecord::from_path(path, true)?;
    println!("Inserting record: {:#?}", record);

    record.upsert(&pool).await?;
    println!("✅ Inserted into database");

    Ok(())
}
