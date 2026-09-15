//! Tools for running computer processes locally or remotely via SSH

// TODO: Examples:
//      * interacting with a local process
//      * interacting with a remote process
//      * file transfers

// TODO: Document UTF8 is required for all text IO

#![allow(clippy::uninit_vec)]
#![allow(unreachable_code)]

use ssh2::{Channel, Session, Sftp, Stream};
use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::mem;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::{self, fd::AsRawFd};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc, mpsc::TryRecvError};
use std::thread;
use std::time;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Ssh(#[from] ssh2::Error),

    #[error("{0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Token representing a computer and how to access it
#[derive(Clone)]
pub enum Computer {
    /// Local computer / operating system
    Local,

    /// Remote computer accessed via Secure Shell Protocol (SSH)
    Remote {
        /// Hostname of the remote computer.
        host: String,

        /// Computer IP address
        addr: SocketAddr,

        /// Login username
        user: String,

        /// User authentication password / key
        auth: String,
    },
}

impl Computer {
    /// Token for the computer / operating system currently running this program
    pub fn new_local() -> Arc<Self> {
        Self::Local.into()
    }
    /// Token for accessing a computer remotely over SSH
    pub fn new_remote(host: String, user: String, auth: String) -> Result<Arc<Self>, Error> {
        let addr = host.to_socket_addrs()?.next().unwrap();
        Ok(Self::Remote {
            host,
            addr,
            user,
            auth,
        }
        .into())
    }
    /// Establish an SSH connection to a remote computer
    fn connect(&self) -> Result<Session, Error> {
        // Unpack the remote computer's information into local variables
        let Self::Remote {
            addr, user, auth, ..
        } = self
        else {
            unreachable!();
        };
        // Establish the SSH connection
        let tcp = TcpStream::connect(*addr)?;
        let mut conn = Session::new()?;
        conn.set_tcp_stream(tcp);
        conn.handshake()?;
        conn.userauth_password(user, auth)?;
        Ok(conn)
    }
    /// Zero the authentication token / password out of memory
    fn delete_auth(&mut self) {
        match self {
            Self::Local => {}
            Self::Remote { auth, .. } => {
                // Zero all of the string's data
                unsafe {
                    let vec = auth.as_mut_vec();
                    vec.set_len(vec.capacity());
                    vec.fill(0);
                }
                auth.clear(); // Zero the size too
                *auth = String::new(); // Free the memory allocation
            }
        }
    }
    /// Returns the externally visible hostname of this computer
    pub fn host(&self) -> String {
        match self {
            Self::Local => "localhost".to_string(),
            Self::Remote { host, addr, .. } => {
                if !host.is_empty() {
                    host.to_string()
                } else {
                    format!("{}", addr.ip())
                }
            }
        }
    }
    ///
    pub fn send_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let sess = match self {
            Self::Remote { .. } => self.connect().unwrap(),
            Self::Local => return Ok(()),
        };
        Self::send_file_inner(&sess, path.as_ref())
    }
    fn send_file_inner(sess: &Session, path: &Path) -> Result<(), Error> {
        sess.set_blocking(true);
        let sftp = sess.sftp()?;
        // Get the remote files's modification time stamp (in unix time).
        let remote_mtime = match sftp.stat(path) {
            Ok(metadata) => metadata.mtime,
            Err(err) => match err.code() {
                // ErrorCode #2 is "file not found" error.
                ssh2::ErrorCode::SFTP(2) => {
                    // Ensure that the parent directory exists.
                    if let Some(dir) = path.parent() {
                        remote_create_dir_all(&sftp, dir, 0o775)?;
                    }
                    None
                }
                _ => return Err(err.into()),
            },
        };
        // Get the local file's modification time stamp (in unix time).
        let local_metadata = fs::metadata(path)?;
        let local_mtime = local_metadata.modified()?;
        let local_mtime = local_mtime
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Check if the file is already up-to-date on the remote.
        if Some(local_mtime) == remote_mtime {
            return Ok(());
        }
        // Copy the file to the remote computer.
        let data = fs::read(path)?;
        let mut remote_file = sftp.create(path)?;
        remote_file.write_all(&data)?;
        // Set the permission bits on the remote.
        #[cfg(target_family = "unix")]
        let perm = {
            use os::unix::fs::MetadataExt;
            Some(local_metadata.mode())
        };
        #[cfg(target_family = "windows")]
        let perm = {
            None
            // todo!()
        };
        remote_file.setstat(ssh2::FileStat {
            size: None,
            uid: None,
            gid: None,
            perm,
            atime: None,
            mtime: Some(local_mtime),
        })?;
        Ok(())
    }
    ///
    pub fn recv_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let sess = match self {
            Self::Remote { .. } => self.connect().unwrap(),
            Self::Local => return Ok(()),
        };
        Self::recv_file_inner(&sess, path.as_ref())
    }
    fn recv_file_inner(sess: &Session, path: &Path) -> Result<(), Error> {
        // Create the local parent directory if it doesn't already exist
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
        }
        sess.set_blocking(true);
        let sftp = sess.sftp()?;
        let stat = sftp.stat(path)?;
        assert!(!stat.is_dir());
        // Open and retrieve the file from the remote
        let mut file = sftp.open(path)?;
        let mut data = match stat.size {
            Some(bytes) => Vec::with_capacity(bytes as usize),
            None => Vec::new(),
        };
        file.read_to_end(&mut data)?;
        fs::write(path, &data)?;
        Ok(())
    }
    /// Spawn a new process on this computer
    ///
    /// Argument command is the program file-path followed by its CLI arguments
    pub fn exec(self: Arc<Computer>, command: &[impl AsRef<str>]) -> Result<Box<Process>, Error> {
        Process::new(self, command)
    }
}

fn remote_create_dir_all(sftp: &Sftp, dir: &Path, mode: i32) -> Result<(), Error> {
    // Base case: check if the directory already exists
    match sftp.stat(dir) {
        Ok(stat) => {
            debug_assert!(stat.is_dir());
        }
        Err(err) => match err.code() {
            // ErrorCode #2 is "file not found" error
            ssh2::ErrorCode::SFTP(2) => {
                if let Some(parent) = dir.parent() {
                    // Recursively ensure that the parent directory exists
                    remote_create_dir_all(sftp, parent, mode)?;
                    // Make the target directory
                    sftp.mkdir(dir, mode)?;
                }
            }
            _ => return Err(err.into()),
        },
    }
    Ok(())
}

impl fmt::Debug for Computer {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => fmt.write_str("Local"),
            Self::Remote {
                host,
                addr,
                user,
                auth,
            } => {
                let auth = if auth.is_empty() {
                    format_args!("\"\"")
                } else {
                    format_args!("[hidden]")
                };
                fmt.debug_struct("Remote")
                    .field("host", &host)
                    .field("addr", &addr)
                    .field("user", &user)
                    .field("auth", &auth)
                    .finish()
            }
        }
    }
}

impl Drop for Computer {
    fn drop(&mut self) {
        self.delete_auth(); // Scrub the password on the way out
    }
}

/// Container for an active computer process
///
/// This provides an API for interacting with computer processes,
/// regardless of where the computer is located.
///
/// ## Newlines
/// Lines are terminated by either the newline character '\n' or the end of
/// file. Carriage return characters '\r' are treated as regular text.
///
/// Methods that send lines ensure that a newline is present, and will append
/// the newline character '\n' if necessary.
///
/// Methods that receive lines remove the newline character from the end of
/// each line.
///
/// ## Blocking
///  * Writing to the process’s stdin is always blocking, and also immediately
///    flushes to operating system buffer
///  * Reading from the process’s stdout can be either blocking or non-blocking
///  * Reading from the process’s stderr is always non-blocking
///
/// ## Drop
/// Drop closes the process’s standard input and output channels.
/// This does not kill or wait for dropped processes to terminate.
///
/// User may call `process.wait()` to block until process termination
///
#[derive(Debug)]
pub struct Process {
    computer: Arc<Computer>,
    stdout_buffer: VecDeque<u8>,
    stderr_buffer: VecDeque<u8>,
    inner: ProcessInner,
}
enum ProcessInner {
    Local(Child),
    Remote(RemoteInner),
}
struct RemoteInner {
    session: Session,
    channel: Channel,
    /// Number of threads currently needing non-blocking behavior
    nonblocking: Arc<Mutex<u8>>,
}

impl Process {
    /// Spawn a new process on the given computer
    ///
    /// Argument command is the program file-path followed by its CLI arguments
    pub fn new(
        computer: Arc<Computer>,
        command: &[impl AsRef<str>],
    ) -> Result<Box<Process>, Error> {
        assert!(!command.is_empty(), "argument 'command' is empty");
        let inner = match computer.as_ref() {
            Computer::Local => {
                // Setup the subprocess command.
                let mut cmd = Command::new(command[0].as_ref());
                cmd.args(command[1..].iter().map(|arg| arg.as_ref()));
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                let child = cmd.spawn()?;
                // Set stderr to non-blocking
                change_blocking_fd(child.stderr.as_ref().unwrap().as_raw_fd(), false);
                ProcessInner::Local(child)
            }
            Computer::Remote { .. } => {
                // Assemble the command into a single line
                let mut line = String::with_capacity(
                    command.iter().map(|arg| arg.as_ref().len()).sum::<usize>() + command.len() - 1,
                );
                line.push_str(command[0].as_ref());
                for arg in &command[1..] {
                    line.push(' ');
                    line.push_str(arg.as_ref());
                }
                // Establish a new connection for this program
                let session = computer.connect()?;
                let mut channel = session.channel_session()?;
                // Run the program on the remote computer
                channel.exec(&line)?;
                //
                ProcessInner::Remote(RemoteInner {
                    session,
                    channel,
                    nonblocking: Arc::new(Mutex::new(0)),
                })
            }
        };
        Ok(Box::new(Process {
            computer,
            stdout_buffer: Default::default(),
            stderr_buffer: Default::default(),
            inner,
        }))
    }
    /// Get the computer that this process is running on
    pub fn computer(&self) -> &Arc<Computer> {
        &self.computer
    }
    /// Is this process still running or does it have unread messages on stdout or stderr?
    pub fn is_alive(&mut self) -> Result<bool, Error> {
        let Self {
            inner,
            stdout_buffer,
            stderr_buffer,
            ..
        } = self;
        // Check for buffered & uncollected data
        if !stdout_buffer.is_empty() || !stderr_buffer.is_empty() {
            return Ok(true);
        }
        match inner {
            ProcessInner::Local(child) => {
                // Check for normal exit status code
                let status = child.try_wait()?;
                if status.is_none() {
                    return Ok(true);
                }
                // Process has exited, block for final unread messages
                if let Some(stdout_pipe) = child.stdout.as_mut() {
                    change_blocking_fd(stdout_pipe.as_raw_fd(), true);
                    let mut stdout_data = vec![];
                    stdout_pipe.read_to_end(&mut stdout_data)?;
                    stdout_buffer.append(&mut stdout_data.into());
                }
                if let Some(stderr_pipe) = child.stderr.as_mut() {
                    change_blocking_fd(stderr_pipe.as_raw_fd(), true);
                    let mut stderr_data = vec![];
                    stderr_pipe.read_to_end(&mut stderr_data)?;
                    stderr_buffer.append(&mut stderr_data.into());
                }
                // Process dead & channels EOF, drop them
                mem::take(&mut child.stdin);
                mem::take(&mut child.stdout);
                mem::take(&mut child.stderr);
                //
                Ok(!stdout_buffer.is_empty() || !stderr_buffer.is_empty())
            }
            ProcessInner::Remote(RemoteInner { channel, .. }) => Ok(!channel.eof()),
        }
    }
    /// Close the process’s standard input and output channels
    ///
    /// Note: remote processes only close stdin; they do not close stdout
    pub fn close_stdio(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            ProcessInner::Local(child) => {
                child.stdin.take();
                child.stdout.take();
            }
            ProcessInner::Remote(RemoteInner {
                channel,
                nonblocking,
                ..
            }) => {
                // Block so that it can flush buffers
                let _guard = guard_session_blocking(nonblocking);
                channel.send_eof()?;
            }
        }
        Ok(())
    }
    /// Close the process’s standard input and output channels, send the close
    /// message / kill signal, and block until it terminates
    ///
    /// Returns [true] if the process ended cleanly, or [false] if it was killed
    /// by a signal or if it exited with non-zero status code
    pub fn wait(&mut self) -> Result<bool, Error> {
        self.close_stdio()?;
        match &mut self.inner {
            ProcessInner::Local(child) => {
                // TODO: Either local should kill, or remote should not-kill
                // TODO: Maybe I could support both kill & wait?
                // child.kill()?;
                let status = child.wait()?;
                Ok(status.success())
            }
            ProcessInner::Remote(RemoteInner {
                channel,
                nonblocking,
                ..
            }) => {
                let _guard = guard_session_blocking(nonblocking);
                channel.close()?;
                channel.wait_eof()?; // required to complete before calling wait_close
                channel.wait_close()?;
                //
                let signal = channel.exit_signal()?;
                if signal.exit_signal.is_some() {
                    return Ok(false);
                }
                //
                let status = channel.exit_status()?;
                let success = status == 0;
                Ok(success)
            }
        }
    }
    fn stdin(&mut self) -> Result<&mut dyn Write, Error> {
        Ok(match &mut self.inner {
            ProcessInner::Local(child) => child
                .stdin
                .as_mut()
                .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?,
            ProcessInner::Remote(RemoteInner { channel, .. }) => channel,
        })
    }
    fn stdout(&mut self) -> Result<&mut dyn Read, Error> {
        Ok(match &mut self.inner {
            ProcessInner::Local(child) => child
                .stdout
                .as_mut()
                .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?,
            ProcessInner::Remote(RemoteInner { channel, .. }) => channel,
        })
    }
    /// Note: this affects all streams for remote channels
    fn set_stdout_blocking(&mut self, blocking: bool) {
        match &self.inner {
            ProcessInner::Local(child) => {
                #[cfg(target_family = "unix")]
                {
                    if let Some(stdout) = child.stdout.as_ref() {
                        change_blocking_fd(stdout.as_raw_fd(), blocking);
                    }
                }
                #[cfg(target_family = "windows")]
                {
                    todo!()
                }
            }
            ProcessInner::Remote(RemoteInner {
                session,
                nonblocking,
                ..
            }) => {
                if blocking {
                    set_session_blocking(session, nonblocking);
                } else {
                    set_session_nonblocking(session, nonblocking);
                }
            }
        }
    }
    /// Write to and flush the process’s standard input channel.
    /// This appends a newline (if not already present).
    ///
    /// **Blocks** the calling thread until this operation is completed
    pub fn send_line(&mut self, message: &str) -> Result<(), Error> {
        match self.inner {
            ProcessInner::Local(_) => {
                let stdin = self.stdin()?;
                stdin.write_all(message.as_bytes())?;
                if !message.ends_with('\n') {
                    stdin.write_all(b"\n")?;
                }
                stdin.flush()?;
            }
            ProcessInner::Remote(_) => {
                let stdin = self.stdin()?;
                blocking_loop(|| stdin.write_all(message.as_bytes()))?;
                if !message.ends_with('\n') {
                    blocking_loop(|| stdin.write_all(b"\n"))?;
                }
                blocking_loop(|| stdin.flush())?;
            }
        }
        Ok(())
    }
    /// Write to and flush the process’s standard input channel.
    ///
    /// **Blocks** the calling thread until this operation is completed
    pub fn send_bytes(&mut self, message: &[u8]) -> Result<(), Error> {
        match self.inner {
            ProcessInner::Local(_) => {
                let stdin = self.stdin()?;
                stdin.write_all(message)?;
                stdin.flush()?;
            }
            ProcessInner::Remote(_) => {
                let stdin = self.stdin()?;
                blocking_loop(|| stdin.write_all(message))?;
                blocking_loop(|| stdin.flush())?;
            }
        }
        Ok(())
    }
    /// Read zero or one lines from the process’s standard output channel.
    /// Then this removes the trailing newline.
    ///
    /// **Non-blocking:** returns [None] if a line is not yet available
    pub fn recv_line(&mut self) -> Result<Option<String>, Error> {
        // First check the buffer
        let line = read_line(&mut self.stdout_buffer)?;
        if line.is_some() {
            return Ok(line);
        }
        // Read stdout non-blocking
        self.set_stdout_blocking(false);
        let read_result = read_nonblocking(self.stdout()?);
        self.set_stdout_blocking(true);
        match read_result {
            Ok(data) => {
                self.stdout_buffer.append(&mut data.into());
                read_line(&mut self.stdout_buffer)
            }
            Err(err) => {
                // If EOF then return all remaining data in buffer
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stdout_buffer.is_empty() {
                    let data = mem::take(&mut self.stdout_buffer);
                    Ok(Some(String::from_utf8(data.into())?))
                } else {
                    Err(err.into())
                }
            }
        }
    }
    /// Read an exact number of bytes from the process’s standard output channel
    ///
    /// **Non-blocking:** returns [None] if the data is not yet available
    pub fn recv_bytes(&mut self, bytes: usize) -> Result<Option<Box<[u8]>>, Error> {
        // First check the buffer
        if self.stdout_buffer.len() >= bytes {
            return Ok(Some(self.stdout_buffer.drain(..bytes).collect()));
        }
        // Read stdout non-blocking
        self.set_stdout_blocking(false);
        let chunk = read_nonblocking(self.stdout()?)?;
        self.set_stdout_blocking(true);
        self.stdout_buffer.append(&mut chunk.into());
        // Check if enough data is now available
        if self.stdout_buffer.len() >= bytes {
            Ok(Some(self.stdout_buffer.drain(..bytes).collect()))
        } else {
            Ok(None)
        }
    }
    /// Read one line from the process’s standard output channel.
    /// Then this removes the trailing newline.
    ///
    /// **Blocks** the calling thread until this operation is completed
    pub fn block_line(&mut self) -> Result<String, Error> {
        // First check the buffer
        if let Some(line) = read_line(&mut self.stdout_buffer)? {
            return Ok(line);
        }
        // Take and use the entire current buffer
        let mut stdout_buffer = mem::take(&mut self.stdout_buffer);
        let stdout = self.stdout()?;
        let mut read_buffer = new_buffer();
        // Read loop until newline is received
        loop {
            // Read a chunk of data
            match blocking_loop(|| stdout.read(&mut read_buffer)) {
                Ok(num) => {
                    // Check for end of file, return all remaining data
                    if num == 0 {
                        return Ok(String::from_utf8(stdout_buffer.into())?);
                    }
                    stdout_buffer.extend(&read_buffer[..num]);
                }
                Err(err) => {
                    // Check for end of file, return all remaining data
                    if err.kind() == ErrorKind::BrokenPipe && !stdout_buffer.is_empty() {
                        // Return all remaining data
                        return Ok(String::from_utf8(stdout_buffer.into())?);
                    }
                    return Err(err.into());
                }
            }
            // Check for newline
            if let Some(line) = read_line(&mut stdout_buffer)? {
                self.stdout_buffer = stdout_buffer; // Save remaining data in buffer
                return Ok(line);
            }
        }
        unreachable!()
    }
    /// Read an exact number of bytes from the process’s standard output channel
    ///
    /// **Blocks** the calling thread until this operation is completed
    pub fn block_bytes(&mut self, bytes: usize) -> Result<Box<[u8]>, Error> {
        // First check the local buffer.
        let len = self.stdout_buffer.len();
        if len >= bytes {
            return Ok(self.stdout_buffer.drain(..bytes).collect());
        }
        // Take and prepare the output buffer to hold more data
        let mut buffer: Vec<u8> = mem::take(&mut self.stdout_buffer).into();
        buffer.reserve(bytes - len);
        unsafe {
            buffer.set_len(bytes);
        }
        // Read and return an exact amount of data (blocking)
        let stdout = self.stdout()?;
        blocking_loop(|| stdout.read_exact(&mut buffer[len..]))?;
        Ok(buffer.into())
    }
    /// Read one line from the process’s standard error channel.
    /// Then this removes the trailing newline.
    ///
    /// **Non-blocking:** returns [None] if the next line is not yet available
    pub fn error_line(&mut self) -> Result<Option<String>, Error> {
        // First check the local buffer.
        let line = read_line(&mut self.stderr_buffer)?;
        if line.is_some() {
            return Ok(line);
        }
        match self.read_stderr_nonblocking() {
            Ok(()) => {
                let line = read_line(&mut self.stderr_buffer)?;
                Ok(line)
            }
            Err(err) => {
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stderr_buffer.is_empty() {
                    // If EOF then return remaining content, even though it's not newline terminated
                    let data = mem::take(&mut self.stderr_buffer);
                    let line = Some(String::from_utf8(data.into())?);
                    Ok(line)
                } else {
                    Err(err.into())
                }
            }
        }
    }
    /// Read all available bytes from the process’s standard error channel
    ///
    /// **Non-blocking:** returns an empty vector if nothing is available
    pub fn error_bytes(&mut self) -> Result<Vec<u8>, Error> {
        match self.read_stderr_nonblocking() {
            Ok(()) => Ok(self.stderr_buffer.drain(..).collect()),
            Err(err) => {
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stderr_buffer.is_empty() {
                    let data = mem::take(&mut self.stderr_buffer);
                    return Ok(data.into());
                }
                Err(err.into())
            }
        }
    }
    fn read_stderr_nonblocking(&mut self) -> Result<(), io::Error> {
        let data = match &mut self.inner {
            ProcessInner::Local(child) => {
                let Some(stderr) = child.stderr.as_mut() else {
                    panic!("stderr was forwarded");
                };
                // Local process stderr is always non-blocking
                read_nonblocking(stderr)?
            }
            ProcessInner::Remote(RemoteInner {
                session,
                channel,
                nonblocking,
                ..
            }) => {
                set_session_nonblocking(session, nonblocking);
                let data = read_nonblocking(&mut channel.stderr())?;
                set_session_blocking(session, nonblocking);
                data
            }
        };
        self.stderr_buffer.append(&mut data.into());
        Ok(())
    }
    ///
    pub fn send_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let ProcessInner::Remote(RemoteInner { session, .. }) = &self.inner else {
            return Ok(());
        };
        Computer::send_file_inner(session, path.as_ref())
    }
    ///
    pub fn recv_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let ProcessInner::Remote(RemoteInner { session, .. }) = &self.inner else {
            return Ok(());
        };
        Computer::recv_file_inner(session, path.as_ref())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _error = self.close_stdio();
    }
}

impl fmt::Debug for ProcessInner {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(child) => fmt.debug_tuple("Local").field(child).finish(),
            Self::Remote(_channel) => fmt
                .debug_tuple("Remote")
                .field(&format_args!("ssh2::Channel"))
                .finish(),
        }
    }
}

#[cfg(target_family = "unix")]
fn change_blocking_fd(fd: os::unix::io::RawFd, blocking: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            panic!("libc file control error");
        }
        let error = libc::fcntl(
            fd,
            libc::F_SETFL,
            if blocking {
                flags & !libc::O_NONBLOCK
            } else {
                flags | libc::O_NONBLOCK
            },
        );
        if error < 0 {
            panic!("libc file control error");
        }
    }
}

/// bytes
const BUFFER_SIZE: usize = 8192;

/// Return new uninitialized buffer with length [BUFFER_SIZE] bytes
fn new_buffer() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(BUFFER_SIZE);
    unsafe {
        buffer.set_len(BUFFER_SIZE);
    }
    buffer
}

/// Reads all available data until either EOF or WouldBlock
fn read_nonblocking(pipe: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut len = 0;
    let mut buffer = vec![];
    loop {
        buffer.reserve(BUFFER_SIZE);
        unsafe {
            buffer.set_len(buffer.capacity());
        }
        match pipe.read(&mut buffer[len..]) {
            Ok(num) => {
                len += num;
                if len == 0 {
                    return Err(ErrorKind::BrokenPipe.into());
                } else if len < buffer.len() {
                    unsafe {
                        buffer.set_len(len);
                    }
                    return Ok(buffer);
                } else {
                    // len == buffer.len()
                    // Pipe.read() filled the buffer. Loop and retry with larger buffer
                }
            }
            Err(err) => {
                match err.kind() {
                    ErrorKind::WouldBlock => {
                        unsafe { buffer.set_len(len) };
                        return Ok(buffer);
                    }
                    _ => {
                        return Err(err);
                    }
                };
            }
        }
    }
}

/// Perform a blocking function, under possibly non-blocking conditions.
/// If the given function returns WouldBlock then loop and retry until success.
fn blocking_loop<V>(mut f: impl FnMut() -> Result<V, io::Error>) -> Result<V, io::Error> {
    loop {
        match f() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if err.kind() == ErrorKind::WouldBlock {
                    thread::yield_now();
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
    unreachable!()
}

/// Split off one line from the head of the buffer
fn read_line(buffer: &mut VecDeque<u8>) -> Result<Option<String>, Error> {
    // TODO: convert to unicode one char at a time, for correctness
    if let Some(newline) = buffer.iter().position(|&chr| chr == b'\n') {
        let mut tail = buffer.split_off(newline);
        tail.pop_front(); // Discard the separating newline character.
        let line = mem::replace(buffer, tail);
        let line = String::from_utf8(line.into())?; // Consume the line even if it fails to parse.
        Ok(Some(line))
    } else {
        Ok(None)
    }
}

/// Set SSH session to non-blocking (affects all streams)
fn set_session_nonblocking(session: &Session, nonblocking: &Mutex<u8>) {
    let mut count = nonblocking.lock().unwrap();
    if *count == 0 {
        session.set_blocking(false);
    }
    *count += 1;
}

/// Restore SSH session to blocking
fn set_session_blocking(session: &Session, nonblocking: &Mutex<u8>) {
    let mut count = nonblocking.lock().unwrap();
    *count -= 1;
    if *count == 0 {
        session.set_blocking(true);
    }
}

/// Ensures that SSH session is and remains in blocking mode
fn guard_session_blocking(nonblocking: &Mutex<u8>) -> MutexGuard<'_, u8> {
    loop {
        {
            let inner = nonblocking.lock().unwrap();
            if *inner == 0 {
                return inner;
            }
        }
        thread::yield_now();
    }
}

/// Forward standard error stream
///
/// This starts a new thread ... which dies when this object is dropped
///
/// TODO DOCS
pub struct Forwarder {
    tx: mpsc::Sender<StderrMessage>,
}
// Structure of messages sent to the worker thread
enum StderrMessage {
    Local(ChildStderr),
    Remote {
        session: Session,
        stderr: Stream,
        nonblocking: Arc<Mutex<u8>>,
    },
}
impl Forwarder {
    pub fn new(destination: Box<dyn Write + Send>) -> Self {
        let (tx, rx) = mpsc::channel();
        thread::spawn(|| Self::main(rx, destination));
        Self { tx }
    }
    /// Setup error forwarding for the given process
    ///
    /// Note: this consumes the process’s standard error channel. After
    /// calling this method `error_line` and `error_bytes` can not be called
    /// on the given process. This method can be called only once for each
    /// process.
    pub fn forward_stderr(&self, process: &mut Process) -> Result<(), Error> {
        let message = match &mut process.inner {
            ProcessInner::Local(child) => StderrMessage::Local(
                mem::take(&mut child.stderr).expect("stderr already forwarded"),
            ),
            ProcessInner::Remote(RemoteInner {
                session,
                channel,
                nonblocking,
            }) => StderrMessage::Remote {
                session: session.clone(),
                stderr: channel.stderr(),
                nonblocking: nonblocking.clone(),
            },
        };
        self.tx.send(message).expect("stderr thread crashed");
        Ok(())
    }
    fn main(rx: mpsc::Receiver<StderrMessage>, mut destination: Box<dyn Write>) {
        let mut sources = vec![];
        let mut dead = vec![];
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            // Check for new stderr channels
            match rx.try_recv() {
                Ok(message) => sources.push(message),
                Err(TryRecvError::Empty) => {
                    if sources.is_empty() {
                        thread::yield_now();
                    }
                }
                Err(TryRecvError::Disconnected) => break,
            }
            // Check each stderr channel. Exhaust each channel before moving
            // onto the next, to minimize interleaving channels.
            for (index, source) in sources.iter_mut().enumerate() {
                match source {
                    StderrMessage::Local(stderr) => loop {
                        match stderr.read(&mut buffer) {
                            Ok(size) => {
                                // Check for end of file
                                if size == 0 {
                                    dead.push(index); // Mark this source for removal
                                    break;
                                }
                                destination.write_all(&buffer[..size]).unwrap();
                            }
                            Err(error) => {
                                if error.kind() == ErrorKind::WouldBlock {
                                    break;
                                } else {
                                    panic!("{}", error);
                                }
                            }
                        }
                    },
                    StderrMessage::Remote {
                        session,
                        stderr,
                        nonblocking,
                    } => {
                        set_session_nonblocking(session, nonblocking);
                        loop {
                            let size = stderr.read(&mut buffer).unwrap();
                            if size > 0 {
                                destination.write_all(&buffer[..size]).unwrap();
                            } else {
                                break;
                            }
                        }
                        set_session_blocking(session, nonblocking);
                    }
                }
            }
            // Remove closed channels from the sources list
            for index in mem::take(&mut dead).iter().rev() {
                sources.swap_remove(*index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::sync::Once;

    fn remote_computer_test_asset() -> (Child, Computer) {
        let (server, port) = sshd();
        let keys = SshKeyFiles::new();
        let comp = Computer::Remote {
            host: String::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            user: "dm".to_string(),
            auth: keys.client_private.into_os_string().into_string().unwrap(),
        };
        (server, comp)
    }

    struct SshKeyFiles {
        base_dir: PathBuf,
        server_private: PathBuf,
        server_public: PathBuf,
        client_private: PathBuf,
        client_public: PathBuf,
    }
    impl SshKeyFiles {
        fn new() -> Self {
            let base_dir = std::env::temp_dir().join("test_server");
            if !base_dir.exists() {
                fs::create_dir(&base_dir).unwrap();
            }
            Self {
                server_private: base_dir.join("host_key"),
                server_public: base_dir.join("host_key.pub"),
                client_private: base_dir.join("client_key"),
                client_public: base_dir.join("client_key.pub"),
                base_dir,
            }
        }
    }

    #[cfg(target_family = "unix")]
    static INIT_KEY: Once = Once::new();
    fn init_ssh_keys() {
        INIT_KEY.call_once(|| {
            let keys = SshKeyFiles::new();
            if keys.server_private.exists() {
                fs::remove_file(&keys.server_private).unwrap();
                fs::remove_file(&keys.server_public).unwrap();
                fs::remove_file(&keys.client_private).unwrap();
                fs::remove_file(&keys.client_public).unwrap();
            }
            for path in [&keys.server_private, &keys.client_private] {
                Command::new("ssh-keygen")
                    .args([
                        "-t",
                        "ed25519",
                        "-f",
                        &path.clone().into_os_string().into_string().unwrap(),
                        "-N",
                        "",
                    ])
                    .status()
                    .unwrap();
            }
        });
    }

    #[cfg(target_family = "unix")]
    fn sshd() -> (Child, u16) {
        // Setup new SSH keys
        init_ssh_keys();
        let keys = SshKeyFiles::new();
        // Get a free port
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let port_string = port.to_string();
        mem::drop(listener);
        // Authorize the clients by public key
        let authorized_keys = keys.client_public.with_file_name("authorized_keys");
        let public_key = fs::read(&keys.client_public).unwrap();
        fs::write(&authorized_keys, public_key).unwrap();
        // Configure sshd
        let config = format!(
            "ListenAddress 127.0.0.1
Port {}
HostKey {}
AuthorizedKeysFile {}
StrictModes no
AddressFamily inet
PermitRootLogin no
AuthenticationMethods publickey
PubkeyAuthentication yes
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PidFile none
Subsystem sftp internal-sftp
",
            &port_string,
            keys.server_private.display(),
            authorized_keys.display(),
        );
        let config_file = keys.base_dir.join("test_config");
        let log_file = keys.base_dir.join("sshd.log");
        eprintln!("SSH SERVER LOG FILE: {}", log_file.display());
        fs::write(&config_file, config).unwrap();
        let server = Command::new("/usr/sbin/sshd")
            .args([
                "-D",
                "-e",
                "-E",
                &log_file.into_os_string().into_string().unwrap(),
                "-f",
                &config_file.into_os_string().into_string().unwrap(),
            ])
            .spawn()
            .unwrap();
        thread::sleep(time::Duration::from_millis(250)); // Wait for server startup
        (server, port)
    }

    /// Test the custom implementation of the Debug trait.
    #[test]
    fn passwords_hidden() {
        let comp1 = Computer::Local;
        let comp2 = Computer::Remote {
            host: String::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234),
            user: "unit_test".to_string(),
            auth: "Z".to_string(),
        };

        let debug = format!("{comp1:?}\n{comp2:?}");
        assert!(debug.contains("unit_test"));
        assert!(!debug.contains("Z"));
    }

    #[test]
    fn local_ack() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "-"])).unwrap();
        assert!(proc.is_alive().unwrap());

        // No data yet, should instantly yield (non-blocking).
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        // Send a message. Environment should echo it back to stdout.
        proc.send_line("Hello localhost").unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello localhost");

        // Message consumed, no further messages.
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.wait().unwrap());

        assert!(!proc.is_alive().unwrap());
    }

    #[test]
    fn error_line() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "foobar"])).unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert!(proc.is_alive().unwrap());
        assert!(proc.recv_line().is_err());
        assert!(dbg!(proc.error_line()).unwrap().is_some());
        assert!(!proc.wait().unwrap());
        assert!(!proc.is_alive().unwrap());
    }

    #[test]
    fn new_lines() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "-"])).unwrap();
        proc.send_line("Hello\n\n \nlocalhost\n").unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), " ");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "localhost");
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.wait().unwrap());
    }

    #[test]
    fn eof_line() {
        // Check it can get the last line before an EOF
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["echo", "one\ntwo\nthree"])).unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "one");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "two");
        assert!(proc.is_alive().unwrap());
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "three");
        assert!(dbg!(proc.recv_line()).is_err());
        assert!(!proc.is_alive().unwrap());
        assert!(proc.wait().unwrap());
    }

    #[test]
    fn is_alive() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["sleep", ".3"])).unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert!(proc.is_alive().unwrap());
        proc.close_stdio().unwrap();
        thread::sleep(time::Duration::from_millis(100));
        assert!(proc.is_alive().unwrap());
        proc.wait().unwrap();
        assert!(!proc.is_alive().unwrap());
    }

    #[test]
    fn remote_ack() {
        // First SCP the environment files onto the remote test computer.
        let (_server, comp) = dbg!(remote_computer_test_asset());
        let mut proc = dbg!(Arc::new(comp).exec(&["cat".to_string(), "-".to_string()])).unwrap();
        assert!(proc.is_alive().unwrap());

        thread::sleep(time::Duration::from_millis(100));

        // No data yet, should instantly yield (non-blocking).
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));
        assert!(proc.is_alive().unwrap());

        // Send a message. Environment should echo it back to stdout.
        proc.send_line("Hello remote").unwrap();
        assert!(proc.is_alive().unwrap());
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello remote");
        assert!(proc.is_alive().unwrap());

        // Message consumed, no further messages.
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));
        assert!(proc.is_alive().unwrap());

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.is_alive().unwrap());
        proc.close_stdio().unwrap();
        assert!(proc.is_alive().unwrap());
        assert!(proc.wait().unwrap());
        assert!(!proc.is_alive().unwrap());
    }

    /// Test sending and receiving files.
    #[test]
    fn remote_roundtrip() {
        let (_server, comp) = dbg!(remote_computer_test_asset());
        // Make a new local directory.
        let dir_name = PathBuf::from("test_dir");
        fs::create_dir_all(&dir_name).unwrap();

        // Make a new local file.
        let file_name = dir_name.join("test_file");
        let file_data = "Hello roundtrip!";
        fs::write(&file_name, &file_data).unwrap();

        // Send it to the remote test computer.
        comp.send_file(&file_name).unwrap();

        // Delete the local copy of the file.
        fs::remove_file(&file_name).unwrap();
        fs::remove_dir(&dir_name).unwrap();

        // Retrieve the file from the remote.
        comp.recv_file(&file_name).unwrap();
        let roundtrip = fs::read_to_string(&file_name).unwrap();

        // Cleanup the local files.
        fs::remove_file(&file_name).unwrap();
        fs::remove_dir(&dir_name).unwrap();

        // Check the contents are correct.
        assert_eq!(file_data, roundtrip);
    }

    // Test forwarding stderr to the console. This should print "Hello World!"
    // to the console three times.
    #[test]
    fn forwarder_usage() {
        const EPRINT: &str = "import sys; print('Hello World!', file=sys.stderr, flush=True);";
        const SLEEP: &str = "import time; time.sleep(.2);";
        let prog1 = format!("{EPRINT}{SLEEP}");
        let prog2 = format!("{SLEEP}{EPRINT}");
        let mut proc1 = Arc::new(Computer::Local)
            .exec(&["python", "-c", &prog1])
            .unwrap();
        let fwd = Forwarder::new(Box::new(io::stderr()));
        fwd.forward_stderr(&mut proc1).unwrap();
        thread::sleep(time::Duration::from_millis(100));
        // Check that processes can be added to the forwarder at any time
        let mut proc2 = Arc::new(Computer::Local)
            .exec(&["python", "-c", &prog2])
            .unwrap();
        let mut proc3 = Arc::new(Computer::Local)
            .exec(&["python", "-c", &prog2])
            .unwrap();
        proc3.close_stdio().unwrap();
        fwd.forward_stderr(&mut proc2).unwrap();
        fwd.forward_stderr(&mut proc3).unwrap();
        // Check forwarder remains active for proc2 and proc3 after proc1 terminates
        proc1.wait().unwrap();
        assert!(!proc1.is_alive().unwrap());
        assert!(proc2.is_alive().unwrap());
        assert!(proc3.is_alive().unwrap());
        thread::sleep(time::Duration::from_millis(200));
        assert!(!proc2.is_alive().unwrap());
        assert!(!proc3.is_alive().unwrap());
    }

    // Check all blocking calls, and check that forwarder does not interfere
    #[test]
    fn blocking() {
        const PROG: &str = "import sys; import time;
time.sleep(.2);
print('hello', flush=True);
sys.stdout.buffer.write(b'world!');
1/0";
        let mut proc = Arc::new(Computer::Local)
            .exec(&["python", "-c", PROG])
            .unwrap();
        // Check non-blocking before results are ready.
        assert!(dbg!(proc.error_bytes()).unwrap().is_empty());
        assert!(dbg!(proc.recv_line().unwrap()).is_none());
        assert!(dbg!(proc.recv_bytes(6).unwrap()).is_none());
        // Wait for results.
        assert_eq!(proc.block_line().unwrap(), "hello");
        assert_eq!(proc.block_bytes(6).unwrap(), (*b"world!").into());
        assert!(!dbg!(proc.error_bytes()).unwrap().is_empty()); // div zero error
        assert!(dbg!(proc.recv_line().unwrap()).is_none()); // non-blocking still works
        assert!(dbg!(proc.recv_bytes(1).unwrap()).is_none());
        assert!(!proc.wait().unwrap()); // error code at exit
        // Check all blocking
        // calls: "send_line", "send_bytes", "block_line", "block_bytes",
        // and "is_alive".
        // todo!();
    }
}
