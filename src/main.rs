use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};
use sqlx::{PgPool, postgres::PgQueryResult};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;

/*

THEN:
 * recurse
 * better CLI

DROP TABLE file_record;
CREATE TABLE file_record (
    id SERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    directory TEXT NOT NULL,
    filename TEXT NOT NULL,
    prefix BYTEA NOT NULL,
    size BIGINT NOT NULL,
    modified TIMESTAMPTZ NOT NULL,
    sha1 CHAR(40) NOT NULL,
    UNIQUE (filename,directory,hostname)
);

*/

#[derive(Debug)]
struct FileRecord {
    directory: String,
    filename: String,
    hostname: String,
    prefix: [u8; 64], // first 8 bytes of the file
    prefix_size: usize,
    size: u64,
    modified: DateTime<Utc>,
    sha1: Option<String>, // optional checksum
}

impl FileRecord {
    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref().canonicalize()?;

        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?
            .to_string();

        let directory = path
            .parent()
            .ok_or("unable to find directory")?
            .display()
            .to_string();

        let hostname = hostname::get()?.to_string_lossy().into_owned();

        let metadata = std::fs::metadata(path)?;

        Ok(Self {
            directory: directory,
            filename: filename,
            hostname: hostname,
            prefix: [0; 64],
            prefix_size: 0,
            size: metadata.len(),
            modified: metadata.modified()?.into(),
            sha1: None,
        })
    }

    fn open(&self) -> Result<File, std::io::Error> {
        let mut path = PathBuf::from(self.directory.clone());
        path.push(self.filename.clone());
        File::open(path)
    }

    fn read_prefix(&mut self) -> Result<(), std::io::Error> {
        self.prefix_size = self.open()?.read(&mut self.prefix)?;
        println!("prefix (at read) {:?}", &self.prefix[..self.prefix_size]);
        Ok(())
    }

    fn read_sha1(&mut self) -> Result<(), std::io::Error> {
        let mut hasher = Sha1::new();
        let mut buf = [0u8; 8192];
        let mut fp = self.open()?;
        loop {
            let n = fp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        self.sha1 = Some(format!("{:x}", hasher.finalize()));
        Ok(())
    }

    async fn upsert(&self, pool: &PgPool) -> Result<PgQueryResult, sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO file_record (hostname, directory, filename, prefix, size, modified, sha1)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (filename, directory, hostname)
            DO UPDATE SET
                prefix = EXCLUDED.prefix,
                size = EXCLUDED.size,
                modified = EXCLUDED.modified,
                sha1 = EXCLUDED.sha1
            "#,
            self.hostname,
            self.directory,
            self.filename,
            &self.prefix[..self.prefix_size],
            self.size as i64,
            self.modified,
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

    let mut record = FileRecord::from_path(path)?;
    record.read_sha1()?;
    record.read_prefix()?;
    println!("Inserting record: {:#?}", record);

    record.upsert(&pool).await?;
    println!("✅ Inserted into database");

    Ok(())
}
