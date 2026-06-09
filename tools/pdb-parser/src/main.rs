use pdb::FallibleIterator;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

const NTOSKRNL: &str = r"C:\Windows\System32\ntoskrnl.exe";

static TARGETS: &[(&str, &[&str])] = &[
    (
        "_EPROCESS",
        &[
            "UniqueProcessId",
            "ActiveProcessLinks",
            "ImageFileName",
            "DebugPort",
            "ThreadListHead",
            "Pcb",
            "VadRoot",
        ],
    ),
    (
        "_KTHREAD",
        &["StackBase", "StackLimit", "Teb", "Process", "State"],
    ),
];

struct PdbInfo {
    filename: String,
    guid: String,
    age: u32,
}

fn rva_to_offset(data: &[u8], rva: usize, sections_start: usize, num_sections: usize) -> usize {
    for i in 0..num_sections {
        let s = sections_start + i * 40;
        let vaddr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap()) as usize;
        let vsize = u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap()) as usize;
        let raw = u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap()) as usize;
        if rva >= vaddr && rva < vaddr + vsize {
            return raw + (rva - vaddr);
        }
    }
    rva
}

fn extract_pdb_info(data: &[u8]) -> PdbInfo {
    let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
    let num_sec = u16::from_le_bytes(data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    let opt_size =
        u16::from_le_bytes(data[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let opt_start = e_lfanew + 24;
    let sec_start = opt_start + opt_size;

    let dbg_rva =
        u32::from_le_bytes(data[opt_start + 160..opt_start + 164].try_into().unwrap()) as usize;
    let dbg_size =
        u32::from_le_bytes(data[opt_start + 164..opt_start + 168].try_into().unwrap()) as usize;
    let dbg_offset = rva_to_offset(data, dbg_rva, sec_start, num_sec);

    let num_dbg = dbg_size / 28;
    let mut cv_off = 0usize;
    for i in 0..num_dbg {
        let e = dbg_offset + i * 28;
        let typ = u32::from_le_bytes(data[e + 12..e + 16].try_into().unwrap());
        if typ == 2 {
            cv_off = u32::from_le_bytes(data[e + 24..e + 28].try_into().unwrap()) as usize;
            break;
        }
    }

    assert_eq!(
        &data[cv_off..cv_off + 4],
        b"RSDS",
        "Not an RSDS CodeView entry"
    );

    let d1 = u32::from_le_bytes(data[cv_off + 4..cv_off + 8].try_into().unwrap());
    let d2 = u16::from_le_bytes(data[cv_off + 8..cv_off + 10].try_into().unwrap());
    let d3 = u16::from_le_bytes(data[cv_off + 10..cv_off + 12].try_into().unwrap());
    let d4 = &data[cv_off + 12..cv_off + 20];
    let age = u32::from_le_bytes(data[cv_off + 20..cv_off + 24].try_into().unwrap());

    let guid = format!(
        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    );

    let ns = cv_off + 24;
    let ne = ns + data[ns..].iter().position(|&b| b == 0).unwrap();
    let raw = String::from_utf8_lossy(&data[ns..ne]).to_string();
    let filename = Path::new(&raw)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    PdbInfo {
        filename,
        guid,
        age,
    }
}

fn download_pdb(info: &PdbInfo, cache_dir: &Path) -> Vec<u8> {
    let cache_file = cache_dir.join(format!("{}_{}{:X}.pdb", info.filename, info.guid, info.age));
    if cache_file.exists() {
        eprintln!("[pdb-parser] Cache hit: {}", cache_file.display());
        return fs::read(&cache_file).expect("Failed to read cache");
    }

    let url = format!(
        "https://msdl.microsoft.com/download/symbols/{}/{}{:X}/{}",
        info.filename, info.guid, info.age, info.filename
    );

    eprintln!("[pdb-parser] Downloading: {}", url);
    let bytes = reqwest::blocking::get(&url)
        .expect("HTTP request failed")
        .bytes()
        .expect("Failed to read response bytes")
        .to_vec();

    fs::create_dir_all(cache_dir).ok();
    fs::write(&cache_file, &bytes).ok();
    eprintln!("[pdb-parser] Cached to: {}", cache_file.display());
    bytes
}

fn collect_fields(
    finder: &pdb::TypeFinder,
    fields_idx: pdb::TypeIndex,
    want: &[&str],
    prefix: &str,
    out: &mut HashMap<String, u32>,
) {
    let Ok(typ) = finder.find(fields_idx) else {
        return;
    };
    let Ok(pdb::TypeData::FieldList(list)) = typ.parse() else {
        return;
    };

    for field in &list.fields {
        if let pdb::TypeData::Member(m) = field {
            let name = m.name.to_string().to_string();
            if want.contains(&name.as_str()) {
                out.insert(format!("{}_{}", prefix, name), m.offset as u32);
            }
        }
    }
    if let Some(cont) = list.continuation {
        collect_fields(finder, cont, want, prefix, out);
    }
}

fn parse_offsets(pdb_bytes: &[u8]) -> HashMap<String, u32> {
    let cursor = Cursor::new(pdb_bytes);
    let mut pdb = pdb::PDB::open(cursor).expect("PDB::open failed");

    let type_info = pdb.type_information().expect("No type information stream");
    let mut finder = type_info.finder();

    let mut iter = type_info.iter();
    while let Some(t) = iter.next().expect("type iter error") {
        finder.update(&iter);
        let _ = t;
    }

    let mut offsets: HashMap<String, u32> = HashMap::new();

    let mut iter = type_info.iter();
    while let Some(t) = iter.next().expect("type iter error") {
        if let Ok(pdb::TypeData::Class(cls)) = t.parse() {
            let name = cls.name.to_string().to_string();
            for (target_struct, members) in TARGETS {
                if &name.as_str() == target_struct {
                    if let Some(fields) = cls.fields {
                        let prefix = &target_struct[1..];
                        collect_fields(&finder, fields, members, prefix, &mut offsets);
                    }
                }
            }
        }
    }

    offsets
}

fn write_header(offsets: &HashMap<String, u32>, out_path: &Path) {
    fs::create_dir_all(out_path.parent().unwrap()).ok();
    let mut f = File::create(out_path).expect("Cannot create offsets.h");

    writeln!(f, "#pragma once").unwrap();
    writeln!(f).unwrap();

    let mut keys: Vec<_> = offsets.keys().collect();
    keys.sort();
    for key in keys {
        writeln!(
            f,
            "#define OFFSET_{:<44} 0x{:04X}",
            key.to_uppercase(),
            offsets[key]
        )
        .unwrap();
    }

    eprintln!(
        "[pdb-parser] Wrote {} offsets -> {}",
        offsets.len(),
        out_path.display()
    );
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = manifest_dir.join(r"..\..\driver\offsets.h");
    let cache_dir = manifest_dir.join("cache");

    let ntoskrnl_bytes = fs::read(NTOSKRNL).expect("Failed to read ntoskrnl.exe");
    let info = extract_pdb_info(&ntoskrnl_bytes);

    eprintln!(
        "[pdb-parser] ntoskrnl PDB: {} | GUID: {} | Age: {}",
        info.filename, info.guid, info.age
    );

    let pdb_bytes = download_pdb(&info, &cache_dir);
    let offsets = parse_offsets(&pdb_bytes);

    write_header(&offsets, &output);
}
