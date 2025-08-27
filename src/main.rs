use anyhow::Result;
use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};
use sqlx::PgPool;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;

/*

THEN:
 * when recusing, delete files that are no longer there
 * better CLI

*/

#[derive(Debug)]
struct FileRecord {
    directory: String,
    filename: String,
    hostname: String,
    prefix: [u8; 64],
    prefix_size: usize,
    size: u64,
    modified: DateTime<Utc>,
    sha1: Option<String>, // optional checksum
}

fn vec_to_trunc_or_pad_64(v: Vec<u8>) -> [u8; 64] {
    let mut arr = [0u8; 64];
    let n = v.len().min(64);
    arr[..n].copy_from_slice(&v[..n]);
    arr
}

impl FileRecord {
    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;

        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?
            .to_string();

        let directory = path
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
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

    fn open(&self) -> Result<File> {
        let mut path = PathBuf::from(self.directory.clone());
        path.push(self.filename.clone());
        Ok(File::open(path)?)
    }

    fn read_prefix(&mut self) -> Result<()> {
        self.prefix_size = self.open()?.read(&mut self.prefix)?;
        Ok(())
    }

    fn read_sha1(&mut self) -> Result<()> {
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

    async fn upsert(&self, pool: &PgPool) -> Result<()> {
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
        .await?;
        Ok(())
    }

    async fn is_database_current(&self, pool: &PgPool) -> Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT size, modified
            FROM file_record
            WHERE hostname = $1 AND directory = $2 and filename = $3
            "#,
            self.hostname,
            self.directory,
            self.filename,
        )
        .fetch_optional(pool)
        .await?;

        if let Some(row) = row {
            if self.size == row.size as u64 && self.modified.timestamp() == row.modified.timestamp()
            {
                return Ok(true);
            }
        }

        if let Some(db_record) =
            Self::fetch_by_name(pool, &self.hostname, &self.directory, &self.filename).await?
        {
            if self.modified.timestamp() == db_record.modified.timestamp()
                && self.size == db_record.size
            {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    async fn fetch_by_name(
        pool: &PgPool,
        hostname: &str,
        directory: &str,
        filename: &str,
    ) -> Result<Option<FileRecord>> {
        let row = sqlx::query!(
            r#"
            SELECT hostname, directory, filename, prefix, size, modified, sha1
            FROM file_record
            WHERE hostname = $1 AND directory = $2 and filename = $3
            "#,
            hostname,
            directory,
            filename,
        )
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| FileRecord {
            hostname: r.hostname,
            directory: r.directory,
            filename: r.filename,
            prefix_size: r.prefix.len(),
            prefix: vec_to_trunc_or_pad_64(r.prefix),
            size: r.size as u64,
            modified: r.modified,
            sha1: Some(r.sha1),
        }))
    }
}

async fn visit_file(path: &Path, pool: &PgPool) -> Result<bool> {
    let mut on_disk = FileRecord::from_path(&path)?;
    if !on_disk.is_database_current(&pool).await? {
        on_disk.read_prefix()?;
        on_disk.read_sha1()?;
        on_disk.upsert(pool).await?;
        println!("updating {:?}", path);
    }
    Ok(true)
}

#[async_recursion]
async fn visit_dir(path: &Path, pool: &PgPool) -> Result<bool> {
    let mut list: Vec<String> = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if visit(&path, pool).await? {
            list.push(path.file_name().unwrap().to_string_lossy().to_string());
        }
    }

    let directory = path.canonicalize()?.to_string_lossy().to_string();

    let names: Vec<String> = sqlx::query_scalar!(
        r#"
        DELETE FROM file_record
        WHERE directory = $1 AND filename <> ALL($2)
        RETURNING filename
        "#,
        directory,
        &list,
    )
    .fetch_all(pool)
    .await?;

    for filename in names {
        println!("removing {:?}", filename);
    }

    return Ok(false);
}

async fn visit(path: &Path, pool: &PgPool) -> Result<bool> {
    if let Some(name) = path.file_name() {
        if name.to_string_lossy().starts_with('.') {
            return Ok(false);
        }
    }

    if path.is_symlink() {
        return Ok(false);
    }

    if path.is_dir() {
        return visit_dir(path, pool).await;
    }

    if path.is_file() {
        return visit_file(path, pool).await;
    }

    return Ok(false);
}

#[tokio::main]
async fn main() -> Result<()> {
    let database_url = env::var("DATABASE_URL")
        .expect("please set DATABASE_URL, e.g. postgres://user:pass@localhost/dbname");
    let pool = PgPool::connect(&database_url).await?;

    let mut args = env::args().skip(1);
    let path = args.next().unwrap_or("./corpus".to_string());

    visit(&Path::new(&path), &pool).await?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_from_path_empty() {
        let mut file_record = FileRecord::from_path("./corpus/empty.txt").unwrap();
        assert_eq!(file_record.filename, "empty.txt");
        assert_eq!(file_record.prefix, [0; 64]);
        assert_eq!(file_record.prefix_size, 0);
        assert_eq!(file_record.size, 0);
        assert_eq!(file_record.sha1, None);

        file_record.read_prefix().unwrap();

        assert_eq!(file_record.prefix, [0; 64]);
        assert_eq!(file_record.prefix_size, 0);

        file_record.read_sha1().unwrap();

        assert_eq!(
            file_record.sha1.as_deref().unwrap_or(""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_from_path_short() {
        let mut file_record = FileRecord::from_path("./corpus/short.txt").unwrap();
        assert_eq!(file_record.filename, "short.txt");
        assert_eq!(file_record.prefix, [0; 64]);
        assert_eq!(file_record.prefix_size, 0);
        assert_eq!(file_record.size, 13);
        assert_eq!(file_record.sha1, None);

        file_record.read_prefix().unwrap();

        assert_eq!(
            file_record.prefix,
            [
                72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 10, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(file_record.prefix_size, 13);

        file_record.read_sha1().unwrap();

        assert_eq!(
            file_record.sha1.as_deref().unwrap_or(""),
            "a0b65939670bc2c010f4d5d6a0b3e4e4590fb92b"
        );
    }

    #[test]
    fn test_from_path_long() {
        let mut file_record = FileRecord::from_path("./corpus/long.txt").unwrap();
        assert_eq!(file_record.filename, "long.txt");
        assert_eq!(file_record.prefix, [0; 64]);
        assert_eq!(file_record.prefix_size, 0);
        assert_eq!(file_record.size, 637);
        assert_eq!(file_record.sha1, None);

        file_record.read_prefix().unwrap();

        assert_eq!(
            file_record.prefix,
            [
                72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 10, 72, 101, 108, 108, 111,
                32, 87, 111, 114, 108, 100, 33, 10, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108,
                100, 33, 10, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 10, 72, 101,
                108, 108, 111, 32, 87, 111, 114, 108, 100, 33
            ]
        );
        assert_eq!(file_record.prefix_size, 64);

        file_record.read_sha1().unwrap();

        assert_eq!(
            file_record.sha1.as_deref().unwrap_or(""),
            "83e3bf0f7defc7258a85c38a113be383817aff73"
        );
    }

    async fn database_connection() -> PgPool {
        let database_url = env::var("TEST_DATABASE_URL")
            .expect("please set TEST_DATABASE_URL, e.g. postgres://user:pass@localhost/dbname");
        let pool = PgPool::connect(&database_url).await.unwrap();
        sqlx::query("DELETE FROM file_record")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn test_upsert() {
        let pool = database_connection().await;

        let insert_record = FileRecord {
            directory: "/foo/bar".to_string(),
            filename: "baz.txt".to_string(),
            hostname: "hostname".to_string(),
            prefix: [0; 64],
            prefix_size: 0,
            size: 0,
            modified: Utc.timestamp_opt(1756138427, 0).unwrap(),
            sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
        };
        assert_eq!(insert_record.upsert(&pool).await.unwrap(), ());

        let read_record = FileRecord::fetch_by_name(&pool, "hostname", "/foo/bar", "baz.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_record.hostname, "hostname");
        assert_eq!(read_record.directory, "/foo/bar");
        assert_eq!(read_record.filename, "baz.txt");
        assert_eq!(read_record.prefix, [0; 64]);
        assert_eq!(read_record.prefix_size, 0);
        assert_eq!(read_record.size, 0);
        assert_eq!(
            read_record.sha1.unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(read_record.modified.to_string(), "2025-08-25 16:13:47 UTC");

        let update_record = FileRecord {
            directory: "/foo/bar".to_string(),
            filename: "baz.txt".to_string(),
            hostname: "hostname".to_string(),
            prefix: [
                0x31, 0x32, 0x33, 0x34, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            prefix_size: 5,
            size: 5,
            modified: Utc.timestamp_opt(1756138430, 0).unwrap(),
            sha1: Some("1be168ff837f043bde17c0314341c84271047b31".to_string()),
        };
        assert_eq!(update_record.upsert(&pool).await.unwrap(), ());

        let read_record = FileRecord::fetch_by_name(&pool, "hostname", "/foo/bar", "baz.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_record.hostname, "hostname");
        assert_eq!(read_record.directory, "/foo/bar");
        assert_eq!(read_record.filename, "baz.txt");
        assert_eq!(
            read_record.prefix,
            [
                0x31, 0x32, 0x33, 0x34, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(read_record.prefix_size, 5);
        assert_eq!(read_record.size, 5);
        assert_eq!(
            read_record.sha1.unwrap(),
            "1be168ff837f043bde17c0314341c84271047b31"
        );
        assert_eq!(read_record.modified.to_string(), "2025-08-25 16:13:50 UTC");
    }
}
