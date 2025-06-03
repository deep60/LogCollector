///SIEM Log
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Core log entry structure to normalize logs from different sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    source_type: String,
    source_name: String,
    timestamp: DateTime<Utc>,
    log_level: Option<String>,
    message: String,
    metadata: serde_json::Value,
}

// Trait defining behaviour for log source collectors
pub trait LogCollector: Send {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>>;
    fn stop_collection(&mut self);
    fn is_running(&self) -> bool;
    fn source_name(&self) -> &str;
    fn source_type(&self) -> &str;
}

// Log processor function type that will be called for each log entry
type LogProcessorFn = Arc<dyn Fn(LogEntry) + Send + Sync>;

// File Log Collector
pub struct FileLogCollector {
    path: PathBuf, 
    follow: bool,
    running: bool,
    processor: LogProcessorFn,
    source_name: String,
}

impl FileLogCollector {
    pub fn new<P: AsRef<Path>>(path: P, follow: bool, processor: LogProcessorFn) -> Self {
        FileLogCollector {
            path: path.as_ref().to_path_buf(),
            follow,
            running: false,
            processor,
            source_name: path.as_ref().to_string_lossy().to_string(),
        }
    }
}

impl LogCollector for FileLogCollector {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        let path = self.path.clone();
        let follow = self.follow;
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();

        thread::spawn(move || {
            if let Err(e) = collect_file_logs(&path, follow, processor, &source_name) {
                eprintln!("Error collecting logs from file {}: {}", path.display(), e);
            }
        });

        Ok(())
    }

    fn stop_collection(&mut self) {
        self.running = false;
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn source_type(&self) -> &str {
        "file"
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

/// Syslog UDP Collector
pub struct SyslogUdpCollector {
    bind_addr: SocketAddr,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: String,
}

impl SyslogUdpCollector {
    pub fn new(bind_addr: SocketAddr, processor: LogProcessorFn) -> Self {
        SyslogUdpCollector {
            bind_addr, 
            running: Arc::new(Mutex::new(false)),
            processor, 
            source_name: format!("syslog-udp-{}", bind_addr),
        }
    }
}

impl LogCollector for SyslogUdpCollector {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(());
        }

        *running = true;
        let addr = self.bind_addr;
        let running_clone = self.running.clone();
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();

        thread::spawn(move || {
            if let Err(e) = collect_syslog_udp(addr, running_clone, processor, &source_name) {
                eprintln!("Error collecting logs from UDP syslog {}: {}", addr, e);
            }
        }); 

        Ok(())
    }

    fn stop_collection(&mut self) {
        let mut running = self.running .lock().unwrap();
        *running = false;
    }

    fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    fn source_type(&self) -> &str {
        "syslog-udp"
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

/// Syslog tcp collector
pub struct SyslogTcpCollector {
    bind_addr: SocketAddr, 
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: String,
}

impl SyslogTcpCollector {
    pub fn new(bind_addr: SocketAddr, processor: LogProcessorFn) -> Self {
        SyslogTcpCollector {
            bind_addr,
            running: Arc::new(Mutex::new(false)),
            processor,
            source_name: format!("syslog-tcp-{}", bind_addr),
        }
    }
}

impl LogCollector for SyslogTcpCollector {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(());
        }

        *running = true;
        let addr = self.bind_addr;
        let running_clone = self.running.clone();
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();

        thread::spawn(move || {
            if let Err(e) = collect_syslog_tcp(addr, running_clone, processor, &source_name) {
                eprintln!("Error collecting logs from TCP syslog {}: {}", addr, e);
            }
        });

        Ok(())
    }

    fn stop_collection(&mut self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    fn source_type(&self) -> &str {
        "syslog-tcp"
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

/// HTTP Log collector (for API based collection)
pub struct HttpLogCollector {
    bind_addr: SocketAddr,
    endpoint: String,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: String,
}

impl HttpLogCollector {
    pub fn new(bind_addr: SocketAddr, endpoint: String, processor: LogProcessorFn) -> Self {
        HttpLogCollector {
            bind_addr,
            endpoint: endpoint.clone(),
            running: Arc::new(Mutex::new(false)),
            processor,
            source_name: format!("http-{}: {}", bind_addr, endpoint),
        }
    }
}

impl LogCollector for HttpLogCollector {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(())
        }

        *running = true;
        let addr = self.bind_addr;
        let endpoint = self.endpoint.clone();
        let running_clone = self.running.clone(); 
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();
        
        thread::spawn(move || {
            if let Err(e) = collect_http_logs(addr, endpoint.as_str(), running_clone, processor, &source_name) {
                eprintln!("Error collecting logs from HTTP endpoint {}: {}", addr, e);
            }
        });

        Ok(())
    }

    fn stop_collection(&mut self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    fn source_type(&self) -> &str {
        "http"
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

/// Implementation details for each collector
fn collect_file_logs(
    path: &Path,
    follow: bool,
    processor: LogProcessorFn,
    source_name: &str,
    ) -> Result<(), Box<dyn Error>> {

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                  // EOF reached
                if !follow {
                    break;
                }

                // when following, wait for more content
                thread::sleep(Duration::from_millis(100));
            }

            Ok(_) => {
                  // Process the line
                let log_entry = LogEntry {
                    source_type: "file".to_string(),
                    source_name: source_name.to_string(),
                    timestamp: Utc::now(),
                    log_level: extract_log_level(&line),
                    message: line.trim().to_string(),
                    metadata: serde_json::json!({
                        "path": path.to_string_lossy().to_string(),
                    }),
                };

                processor(log_entry);
            }

            Err(e) => {
                eprintln!("Error reading from file {}: {}", path.display(), e);
                if !follow {
                    return Err(e.into());
                }

                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    Ok(())
}

fn collect_syslog_udp(
    addr: SocketAddr,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: &str,
    ) -> Result<(), Box<dyn Error>> {

    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut buf = [0; 4096];

    while *running.lock().unwrap() {
        match socket.recv_from(&mut buf) {
            Ok((size, peer_addr)) => {
                if size > 0 {
                    let message = String::from_utf8_lossy(&buf[0..size]).to_string();

                    let log_entry = LogEntry {
                        source_type: "syslog-udp".to_string(),
                        source_name: source_name.to_string(),
                        timestamp: Utc::now(),
                        log_level: extract_log_level(&message),
                        message,
                        metadata: serde_json::json!({
                            "peer_addr": peer_addr.to_string(),
                        }),
                    };

                    processor(log_entry);
                }
            }

            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // Timeout, just continue the loop
                continue;
            }

            Err(e) => {
                eprintln!("Error receiving UDP syslog data: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn collect_syslog_tcp(
    addr: SocketAddr,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: &str,
    ) -> Result<(), Box<dyn Error>> {

    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;

    while *running.lock().unwrap() {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                let processor_clone = processor.clone();
                let source_name_clone = source_name.to_string();

                thread::spawn(move || {
                    handle_tcp_connection(stream, peer_addr, processor_clone, &source_name_clone);
                });
            }

            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No connection available, sleep a bit and try again
                thread::sleep(Duration::from_millis(100));
            } 

            Err(e) => {
                eprintln!("Error accepting TCP Connection: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn handle_tcp_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    processor: LogProcessorFn,
    source_name: &str,
    ) {

    let reader = BufReader::new(stream);

    for line in reader.lines() {
        match line {
            Ok(message) => {
                let log_entry = LogEntry {
                    source_type: "syslog-tcp".to_string(),
                    source_name: source_name.to_string(),
                    timestamp: Utc::now(),
                    log_level: extract_log_level(&message),
                    message,
                    metadata: serde_json::json!({
                        "peer_addr": peer_addr.to_string(),
                    }),
                };

                processor(log_entry)
            }

            Err(e) => {
                eprintln!("Error reading from TCP connection: {}", e);
                break;
            }
        }
    }
}

fn collect_http_logs(
    addr: SocketAddr,
    endpoint: &str,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: &str,
    ) -> Result<(), Box<dyn Error>> {
    // This is a simplified implementation - a proper one would use a framework like actix-web
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;

    while *running.lock().unwrap() {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                let processor_clone = processor.clone();
                let source_name_clone = source_name.to_string();
                let enpoint_clone = endpoint.to_string();
                let running_clone = running.clone();

                thread::spawn(move || {
                    handle_http_connection(stream, peer_addr, running_clone, processor_clone, &source_name_clone, &enpoint_clone);
                });
            }

            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No connection available, sleep a bit and try again
                thread::sleep(Duration::from_millis(100));
            }

            Err(e) => {
                eprintln!("Error accepting HTTP Connection: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn handle_http_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    _running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: &str,
    endpoint: &str,
    ) {
    // This is a very simplified HTTP handler - real implementation would use a proper HTTP parser
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();

    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    // Very basic check for the endpoint
    if !request_line.contains(endpoint) {
        return;
    }

    // Skip headers
    let mut line = String::new();
    while reader.read_line(&mut line).is_ok() && line.trim() != "" {
        line.clear();
    }

    // Read the body
    let mut body = String::new();
    if reader.read_to_string(&mut body).is_err() {
        return;
    }

      // Process the body as a log entry
    let log_entry = LogEntry {
        source_type: "http".to_string(),
        source_name: source_name.to_string(),
        timestamp: Utc::now(),
        log_level: None,
        message: body,
        metadata: serde_json::json!({
            "peer_addr": peer_addr.to_string(),
            "source": source_name,
        }),
    };

    processor(log_entry);
}

/// Windows Event log collector (basic implementation)
#[cfg(target_os = "windows")]
pub struct WindowEventLogCollector {
    channel: String,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: String,
}

#[cfg(target_os = "windows")]
impl WindowEventLogCollector {
    pub fn new(channel: String, processor: LogProcessorFn) -> Self {
        WindowEventLogCollector {
            channel: channel.clone(),
            running: Arc::new(Mutex::new(false)),
            processor,
            source_name: format!("windows-event-{}", channel),
        }
    }
}

#[cfg(target_os = "windows")]
impl LogCollector for WindowEventLogCollector {
    fn start_collection(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(())
        }

        *running = true;
        let channel = self.channel.clone();
        let running_clone = self.running.clone();
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();

        thread::spawn(move || {
            if let Err(e) = collect_windows_event_logs(&channel, running_clone, processor, &source_name) {
                eprintln!("Error collecting logs from windows Event channel {}: {}", channel, e);
            }
        });

        Ok(())
    }

    fn stop_collection(&mut self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    fn source_type(&self) -> &str {
        "windows-event"
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_event_logs(
    channel: &str,
    running: Arc<Mutex<bool>>,
    processor: LogProcessorFn,
    source_name: &str,
    ) -> Result<(), Box<dyn Error>> {
    /// This is a placeholder - a real implementation would use the windows event log API 
    /// For demonstation purposes, we'll simulate reading events
    while *running.lock().unwrap() {
        /// Simulate reading a Window event
        let log_entry = LogEntry {
            source_type: "windows-event".to_string(),
            source_name: source_name.to_string(),
            timestamp: Utc::now(),
            log_level: Some("Information".to_string()),
            message: format!("Simulated Windows Event from channel {}", channel),
            metadata: serde_json::json!({
                "channel": channel,
                "event_id": 1000,
                "provider": "Microsoft-Windows-Security-Auditing",
            }),
        };
        processor(log_entry);

        thread::sleep(Duration::from_secs(5));
    }

    Ok(())
}

/// Helper Function
fn extract_log_level(message: &str) -> Option<String> {
    //Simple pattern matching for common log levels
    let message_lower = message.to_lowercase();

    if message_lower.contains("error") || message_lower.contains("[error]") {
        Some("ERROR".to_string())
    } else if message_lower.contains("warn") || message_lower.contains("[warn]") {
        Some("WARN".to_string())
    } else if message_lower.contains("info") || message_lower.contains("[info]") {
        Some("INFO".to_string())
    } else if message_lower.contains("debug") || message_lower.contains("[debug]") {
        Some("DEBUG".to_string())
    } else if message_lower.contains("trace") || message_lower.contains("[trace]") {
        Some("TRACE".to_string())
    } else {
        None
    }
}

/// STEM log collector manager
pub struct LogCollectorManager {
    collectors: Vec<Box<dyn LogCollector>>,
}

impl LogCollectorManager {
    pub fn new() -> Self {
        LogCollectorManager {
            collectors: Vec::new(),
        }
    }

    pub fn add_collectors(&mut self, collector: Box<dyn LogCollector>) {
        self.collectors.push(collector);
    }

    pub fn start_all_collectors(&mut self) -> Result<(), Box<dyn Error>> {
        for collector in &mut self.collectors {
            collector.start_collection()?;
        }
        Ok(())
    }

    pub fn stop_all_collectors(&mut self) {
        for collector in &mut self.collectors {
            collector.stop_collection();
        }
    }

    pub fn get_running_collectors(&self) -> Vec<&str> {
        self.collectors
            .iter()
            .filter(|c| c.is_running())
            .map(|c| c.source_name())
            .collect()
    }
}

/// Example usage function
pub fn example_usage() {
    // Create a shared log processor function
    let log_processor: LogProcessorFn = Arc::new(|log_entry| {
        println!("[{}] [{}] {}: {}", 
            log_entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            log_entry.log_level.unwrap_or_else(|| "UNKNOWN".to_string()),
            log_entry.source_name,
            log_entry.message
            );
        //In a real SIEM, you would send this log to next stage
        // for normalization, enrichment, and storage
    });

    let mut manager = LogCollectorManager::new();

      // Add a file log collector
    manager.add_collectors(Box::new(FileLogCollector::new(
                "test_logs.log",
                true,  // follow the file 
                log_processor.clone(),
            )));

      // Add a syslog UDP collector
    match "127.0.0.1:5140".parse() {
        Ok(addr) => {
            manager.add_collectors(Box::new(SyslogUdpCollector::new(
                        addr, log_processor.clone(),
                    )));
        }

        Err(e) => eprintln!("Invalid UDP address: {}", e),
    }

   
      // Add a syslog TCP collector
    match "127.0.0.1:1515".parse() {
        Ok(addr) => {
            manager.add_collectors(Box::new(SyslogTcpCollector::new(
                        addr, log_processor.clone(),
                    )));
        }

        Err(e) => eprintln!("Invalid TCP address: {}", e),
    }


      // Add a syslog HTTP collector
    match "127.0.0.1:8081".parse() {
        Ok(addr) => {
            manager.add_collectors(Box::new(HttpLogCollector::new(
                        addr, "/logs".to_string(), log_processor.clone(),
                    )));
        }

        Err(e) => eprintln!("Invalid HTTP address: {}", e),
    }

    /// On windows, add a Windows Event Log collector
    #[cfg(target_os = "windows")]
    manager.add_collectors(Box::new(WindowEventLogCollector::new("Security".to_string(), log_processor.clone())));

      // Start a collectors
    if let Err(e) = manager.start_all_collectors() {
        eprintln!("Error stating collectors: {}", e);
    }

    println!("Running collectors: {:?}", manager.get_running_collectors());

    // In a real application, you would keep the program running
    // For this example, we'll just sleep for a while
    thread::sleep(Duration::from_secs(60));

    // Stop all collectors when done
    manager.stop_all_collectors();
}

fn main() {
    println!("Starting SIEM Log Collector example...");
    example_usage();
    println!("SIEM Log Collector example completed.");
}


