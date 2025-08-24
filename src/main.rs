use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use std::time::UNIX_EPOCH;

use walkdir::WalkDir;
use sha1::{Sha1, Digest};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = if args.len() > 1 {
        &args[1]
    } else {
        "."
    };

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Err(err) = process_file(path) {
                eprintln!("Error processing {:?}: {}", path, err);
            }
        }
    }
}

fn process_file(path: &Path) -> std::io::Result<()> {
    let metadata = path.metadata()?;
    let file_size = metadata.len();

    // last modified time
    let modified = metadata.modified()?;
    let duration = modified.duration_since(UNIX_EPOCH).unwrap_or_default();
    let modified_str = format!("{}", humantime::format_rfc3339(std::time::UNIX_EPOCH + duration));

    let mut file = File::open(path)?;
    let mut buf_reader = BufReader::new(&file);

    // read first 4 bytes
    let mut first_bytes = [0u8; 4];
    let n = buf_reader.read(&mut first_bytes)?;
    let first_hex: String = first_bytes[..n].iter().map(|b| format!("{:02x}", b)).collect();

    // compute sha1
    let mut sha1 = Sha1::new();
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha1.update(&buffer[..count]);
    }
    let sha1_hex = format!("{:x}", sha1.finalize());

    // separate directory and filename
    let dir = path.parent().expect("fixme").canonicalize().map(|p| p.display().to_string()).unwrap_or_default();
    let filename = path.file_name().map(|f| f.to_string_lossy()).unwrap_or_default();

    println!(
        "dir={} | filename={} | size={} | first4={} | modified={} | sha1={}",
        dir,
        filename,
        file_size,
        first_hex,
        modified_str,
        sha1_hex
    );

    Ok(())
}
