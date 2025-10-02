/// Tool to read and display leaves.dat in human-readable format
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const LEAF_SIZE: usize = 32; // Hash size
const ENTRY_SIZE: usize = LEAF_SIZE + 1; // Hash + existence flag

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let data_file = if args.len() > 1 {
        &args[1]
    } else {
        "demo_data/leaves.dat"
    };

    println!("🔍 Reading leaves.dat file");
    println!("{}", "=".repeat(80));
    println!("File: {}\n", data_file);

    if !Path::new(data_file).exists() {
        eprintln!("❌ Error: File '{}' not found", data_file);
        eprintln!("\nUsage: cargo run --example read_leaves [path/to/leaves.dat]");
        eprintln!("Default: cargo run --example read_leaves");
        std::process::exit(1);
    }

    let mut file = File::open(data_file)?;
    let file_size = file.metadata()?.len();

    println!("📊 File Information:");
    println!("   Size: {} bytes", file_size);
    println!(
        "   Entry size: {} bytes (1 byte flag + 32 byte hash)",
        ENTRY_SIZE
    );
    println!();

    // Read entries
    let mut leaf_index = 0;
    let mut found_leaves = 0;
    let mut buffer = vec![0u8; ENTRY_SIZE];

    println!("📝 Leaves Found:");
    println!("{}", "-".repeat(80));

    loop {
        // Calculate position for this leaf
        let position = leaf_index * ENTRY_SIZE;

        // Stop if we're beyond the file
        if position >= file_size as usize {
            break;
        }

        // Seek to position
        file.seek(SeekFrom::Start(position as u64))?;

        // Try to read an entry
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read < ENTRY_SIZE {
            break;
        }

        // Check existence flag
        let exists = buffer[0] == 1;

        if exists {
            // Extract the hash (32 bytes after the flag)
            let hash = &buffer[1..ENTRY_SIZE];
            let hash_hex = hex::encode(hash);

            println!("Leaf {:4}: {}", leaf_index, hash_hex);
            found_leaves += 1;
        }

        leaf_index += 1;

        // Stop if we've checked enough entries without finding any
        if leaf_index > 100 && found_leaves == 0 {
            break;
        }
    }

    if found_leaves == 0 {
        println!("   No leaves found (empty tree)");
    }

    println!();
    println!("{}", "=".repeat(80));
    println!("📊 Summary:");
    println!("   Total leaves found: {}", found_leaves);
    println!("   Last checked index: {}", leaf_index - 1);

    // Show file format info
    println!();
    println!("💡 File Format:");
    println!("   Each entry is {} bytes:", ENTRY_SIZE);
    println!("   - Byte 0: Existence flag (0x01 = exists, 0x00 = empty)");
    println!("   - Bytes 1-32: Leaf hash (32 bytes)");
    println!();
    println!("   Entries are stored sequentially.");
    println!("   Memory-mapped for fast access.");

    Ok(())
}
