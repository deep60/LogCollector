
// Trait defining behaviour for log source collectors
pub trait LogCollector: Send {}

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
        let aadr = self.bind_addr;
        let running_clone = self.running.clone();
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();

        thread::spawn(move || {
            if let Err(e) = collect_syslog_tcp(addr, running_close, processor, &source_name) {
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
    pub fn new(bind_addr: SocketAddr, endpoint: String, processor: LogProcessorFn) -> Self {
        HttpLogCollector {
            bind_addr,
            endpoint,
            running: Arc::new(Mutex::new(false)),
            processor,
            source_name: format!("http-{}{}", bind_addr, endpoint),
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
        let aadr = self.bind_addr;
        let endpoint = self.endpoint.clone();
        let running_clone = self.running.clone(); 
        let processor = self.processor.clone();
        let source_name = self.source_name.clone();
        
        thread::spawn(move || {
            if let Err(e) = collect_http_logs(addr, running_close, processor, &source_name) {
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

    let mut file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                /// EOF reached
                if !follow {
                    break;
                }

                /// when following, wait for more content
                thread::sleep(Duration::from_millis(100));
            }

            Ok(_) => {
                /// Process the line
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
                    let message = String::from_utf8_lossy(&buf[0..sizee]).to_string();

                    let log_entry = LogEntry {
                        source_type: "syslog-udp".to_string(),
                        source_name: source_name.to_string(),
                        timestamp: Utc::now(),
                        log_level: extract_log_level(&message),
                        message,
                        metadata: serde_json::json!({
                            "path_addr": path_addr.to_string(),
                        }),
                    };

                    processor(log_entry);
                }
            }

            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                /// Timeout, just continue the loop
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

            Err(e) if e.kind = io::ErrorKind::WouldBlock => {
                /// Timeout just continue the loop
                continue;
            }
        }
    }
}
