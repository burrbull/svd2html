/// Generates a webpage for a given SVD file containing details on every
/// peripheral and register and their level of coverage.
use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use liquid::{
    model::{object, Scalar},
    Object,
};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use svd_parser::{
    expand::{derive_peripheral, Index},
    svd::{Access, Cluster, Register, RegisterInfo, WriteConstraint},
};

fn hex(val: u64) -> String {
    format!("0x{val:x}")
}

fn generate_index_page(devices: &Object, writer: &mut dyn Write) -> anyhow::Result<()> {
    println!("Generating Index");
    let template_file = include_str!("makehtml.index.template.html");
    let template = liquid::ParserBuilder::with_stdlib()
        .build()
        .unwrap()
        .parse(template_file)
        .unwrap();
    let globals = liquid::object!({ "devices": devices });
    template.render_to(writer, &globals)?;
    Ok(())
}

fn generate_device_page(device: &Object, writer: &mut dyn Write) -> anyhow::Result<()> {
    let template_file = include_str!("makehtml.template.html");
    let template = liquid::ParserBuilder::with_stdlib()
        .build()
        .unwrap()
        .parse(template_file)
        .unwrap();
    let globals = liquid::object!({ "device": device });
    template.render_to(writer, &globals)?;
    Ok(())
}

fn short_access(accs: &str) -> &str {
    match accs {
        "read-write" => "rw",
        "read-only" => "r",
        "write-only" => "w",
        _ => "N/A",
    }
}

trait GetI64 {
    fn get_i64(&self, key: &str) -> Option<i64>;
    fn get_str(&self, key: &str) -> Option<Cow<str>>;
}

impl GetI64 for Object {
    fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key)
            .and_then(|v| v.as_view().as_scalar())
            .and_then(|s| s.to_integer())
    }
    fn get_str(&self, key: &str) -> Option<Cow<str>> {
        self.get(key)
            .and_then(|v| v.as_view().as_scalar())
            .map(|s| s.into_cow_str())
    }
}

/// Given a cluster, returns a list of all registers inside the cluster,
/// with their names updated to include the cluster index and their address
/// offsets updated to include the cluster address offset.
/// The returned register nodes are as though they were never in a cluster.
pub fn expand_cluster(ctag: &Cluster) -> Vec<Register> {
    match ctag {
        Cluster::Single(c) => {
            let mut registers: Vec<Register> = c.registers().cloned().collect();
            let cluster_addr = c.address_offset;
            for r in &mut registers {
                r.name = format!("{} [0]", r.name);
                r.address_offset = cluster_addr + r.address_offset;
            }
            registers
        }
        Cluster::Array(c, d) => {
            let mut registers: Vec<Register> = c.registers().cloned().collect();
            for (i, cluster_idx) in d.indexes().enumerate() {
                let cluster_addr = c.address_offset + (i as u32) * d.dim_increment;
                for r in &mut registers {
                    r.name = format!("{} [{cluster_idx}]", r.name);
                    r.address_offset = cluster_addr + r.address_offset;
                }
            }
            registers
        }
    }
}

pub fn parse_register_array(rtag: &Register, registers: &mut Vec<Object>) {
    match rtag {
        Register::Single(r) => {
            let register = parse_register(r);
            registers.push(register);
        }
        Register::Array(r, d) => {
            let mut r = r.clone();
            for (i, idx) in d.indexes().enumerate() {
                r.name = r.name.replace("%s", &idx);
                r.address_offset = r.address_offset + (i as u32) * d.dim_increment;
                r.description = r.description.map(|d| d.replace("%s", &idx));
                let register = parse_register(&r);
                registers.push(register);
            }
        }
    }
}

pub fn parse_register(rtag: &RegisterInfo) -> Object {
    let mut fields = Vec::new();
    let mut register_fields_total = 0;
    let mut register_fields_documented = 0;
    let raccs = rtag
        .properties
        .access
        .map(Access::as_str)
        .unwrap_or("Unspecified");

    let mut flds = rtag.fields().collect::<Vec<_>>();
    flds.sort_by_key(|f| f.bit_offset());

    for &ftag in &flds {
        register_fields_total += 1;

        let foffset = ftag.bit_offset();
        let faccs = ftag.access.map(Access::as_str).unwrap_or(raccs);
        let enums = ftag.enumerated_values.get(0);
        let wc = &ftag.write_constraint;
        let mut doc = String::new();
        if enums.is_some() || wc.is_some() || faccs == "read-only" {
            register_fields_documented += 1;
            if let Some(enums) = enums.as_ref() {
                doc = "Allowed values:<br>".to_string();
                if let Some(_dfname) = enums.derived_from.as_ref() {
                    todo!()
                }

                for value in &enums.values {
                    doc += "<strong>";
                    doc += &value.value.unwrap().to_string();
                    doc += ": ";
                    doc += &value.name;
                    doc += "</strong>: ";
                    doc += value.description.as_deref().unwrap_or("");
                    doc += "<br>"
                }
            } else if let Some(WriteConstraint::Range(wcrange)) = wc.as_ref() {
                let mn = hex(wcrange.min);
                let mx = hex(wcrange.max);
                doc = format!("Allowed values: {mn}-{mx}");
            }
        }
        fields.push(object!({
            "name": ftag.name,
            "offset": foffset,
            "width": ftag.bit_width(),
            "description": ftag.description,
            "doc": doc,
            "access": faccs,
        }));
    }

    let mut table = vec![vec![object!({"name": "", "width": 1, "doc": false}); 16]; 2];

    for &ftag in flds.iter().rev() {
        let foffset = ftag.bit_offset();
        let faccs = ftag.access.map(Access::as_str).unwrap_or(raccs);
        let access = short_access(faccs);
        let fwidth = ftag.bit_width();
        let fdoc = !ftag.enumerated_values.is_empty() || ftag.write_constraint.is_some();
        for idx in foffset..(foffset + fwidth) {
            let trowidx = ((31 - idx) / 16) as usize;
            let tcolidx = (15 - (idx % 16)) as usize;
            let separated = foffset < 16 && foffset + fwidth > 16;
            let tcell = object!({
                "name": ftag.name,
                "doc": fdoc,
                "access": access,
                "separated": separated,
            });
            table[trowidx][tcolidx] = tcell;
        }
    }

    for trow in table.iter_mut() {
        let mut idx = 0;
        while idx < trow.len() - 1 {
            if trow[idx].get("name") == trow[idx + 1].get("name") {
                let mut width = trow[idx].get_i64("width").unwrap();
                width += 1;
                trow[idx].insert("width".into(), Scalar::new(width).into());
                trow.remove(idx + 1);
                continue;
            }
            idx += 1
        }
    }
    let table = vec![
        object!({"headers": (16..32).rev().collect::<Vec<_>>(), "fields": table[0]}),
        object!({"headers": (0..16).rev().collect::<Vec<_>>(), "fields": table[1]}),
    ];

    let width = if register_fields_total > 0 {
        100. * (register_fields_documented as f64 / register_fields_total as f64)
    } else {
        100.
    };

    object!({
        "name": rtag.name,
        "offset": hex(rtag.address_offset as _),
        "description": rtag.description,
        "resetValue": rtag.properties.reset_value.unwrap(),
        "access": raccs,
        "fields": fields,
        "table": table,
        "fields_total": register_fields_total,
        "fields_documented": register_fields_documented,
        "width": width,
    })
}

pub fn parse_device(svdfile: impl AsRef<Path>) -> anyhow::Result<Object> {
    let svdfile = svdfile.as_ref();
    let mut file = File::open(svdfile)?;
    let temp = file.metadata()?.st_mtime();
    let mut xml = String::new();
    file.read_to_string(&mut xml)?;
    let device = svd_parser::parse(&xml)?;
    let index = Index::create(&device);
    let mut peripherals = Object::new();
    let mut device_fields_total = 0;
    let mut device_fields_documented = 0;
    for ptag in &device.peripherals {
        let mut registers = Vec::new();
        let mut peripheral_fields_total = 0;
        let mut peripheral_fields_documented = 0;
        let pname = &ptag.name;
        let ptag = if let Some(dfname) = ptag.derived_from.as_ref() {
            let mut ptag = ptag.clone();
            derive_peripheral(&mut ptag, dfname, &index)?;
            Cow::Owned(ptag)
        } else {
            Cow::Borrowed(ptag)
        };
        for ctag in ptag.clusters() {
            for rtag in expand_cluster(ctag) {
                parse_register_array(&rtag, &mut registers);
            }
        }
        for rtag in ptag.registers() {
            parse_register_array(&rtag, &mut registers);
        }

        for register in &registers {
            peripheral_fields_total += register.get_i64("fields_total").unwrap();
            peripheral_fields_documented += register.get_i64("fields_documented").unwrap();
        }

        let width = if peripheral_fields_total > 0 {
            100. * (peripheral_fields_documented as f64 / peripheral_fields_total as f64)
        } else {
            100.
        };
        peripherals.insert(
            pname.into(),
            object!({
                "name": pname,
                "base": ptag.base_address,
                "description": ptag.description,
                "registers": registers,
                "fields_total": peripheral_fields_total,
                "fields_documented": peripheral_fields_documented,
                "last-modified": temp,
                "svdfile": svdfile.to_str().unwrap(),
                "width": width,
            })
            .into(),
        );
        device_fields_total += peripheral_fields_total;
        device_fields_documented += peripheral_fields_documented;
    }

    //let mut object = Object::new();
    //object.insert("name", Value::scalar(device.name.to_string()));
    let width = if device_fields_total > 0 {
        100. * (device_fields_documented as f64 / device_fields_total as f64)
    } else {
        100.
    };
    Ok(object!({
        "name": device.name,
        "peripherals": peripherals,
        "fields_total": device_fields_total,
        "fields_documented": device_fields_documented,
        "width": width,
    }))
}

pub fn process_svd(svdfile: impl AsRef<Path>) -> anyhow::Result<Object> {
    println!("Processing {}", svdfile.as_ref().to_str().unwrap());
    parse_device(svdfile)
}

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to write HTML files to
    htmldir: PathBuf,

    /// Path to patched SVD files
    svdfiles: PathBuf,
}

pub fn generate_if_newer(device: &Object, htmldir: &Path) -> anyhow::Result<()> {
    let pagename = format!("{}.html", device.get_str("name").unwrap());
    let filename = htmldir.join(&pagename);
    if !filename.is_file()
        || std::fs::metadata(&filename)?.st_mtime() < device.get_i64("last-modified").unwrap()
    {
        println!("Generating {pagename}");
        let svdfile = device.get_str("svdfile").unwrap();
        let svdfile = Path::new(svdfile.as_ref());
        let svdfile_name = svdfile.file_name().unwrap();
        let mut file = std::fs::File::create(filename)?;
        generate_device_page(device, &mut file)?;
        std::fs::copy(svdfile, &htmldir.join(svdfile_name))?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut svdfiles = Vec::new();
    if args.svdfiles.is_dir() {
        for entry in std::fs::read_dir(args.svdfiles)? {
            let entry = entry?;
            let path = entry.path();
            if path.ends_with(".patched") {
                svdfiles.push(path);
            }
        }
    }
    let devices = svdfiles
        .par_iter()
        .map(|f| {
            let device = process_svd(f).unwrap();
            generate_if_newer(&device, &args.htmldir).unwrap();
            device
        })
        .collect::<Vec<_>>();

    let mut index_object = Object::new();
    for d in devices {
        let k = d.get_str("name").unwrap().to_string().into();
        index_object.insert(k, d.into());
    }
    let mut file = std::fs::File::create(args.htmldir.join("index.html"))?;
    generate_index_page(&index_object, &mut file)?;
    Ok(())
}
