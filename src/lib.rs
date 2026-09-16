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
use std::path::{Path, PathBuf};
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

        /// User authentication password
        auth: String,

        /// Client's private key file
        key: PathBuf,
    },
}

impl Computer {
    /// Token for the computer / operating system currently running this program
    pub fn new_local() -> Arc<Self> {
        Self::Local.into()
    }
    /// Token for accessing a computer remotely over SSH
    pub fn new_remote(host: String, user: String, key: PathBuf) -> Result<Arc<Self>, Error> {
        let addr = host.to_socket_addrs()?.next().unwrap();
        let auth = String::new();
        Ok(Self::Remote {
            host,
            addr,
            user,
            auth,
            key,
        }
        .into())
    }
    /// Establish an SSH connection to a remote computer
    fn connect(&self) -> Result<Session, Error> {
        // Unpack the remote computer's information into local variables
        let Self::Remote {
            addr,
            user,
            auth,
            key,
            ..
        } = self
        else {
            unreachable!();
        };
        // Establish the SSH connection
        let tcp = TcpStream::connect(*addr)?;
        let mut conn = Session::new()?;
        conn.set_tcp_stream(tcp);
        conn.handshake()?;
        if key != &PathBuf::new() {
            conn.userauth_pubkey_file(user, None, &key, None)?;
        } else if !auth.is_empty() {
            conn.userauth_password(user, auth)?;
        }
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
            Self::Remote { .. } => self.connect()?,
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
                key,
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
                    .field("key", &key)
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

impl Error {
    fn eof(&self) -> bool {
        match self {
            Self::Io(error) => {
                matches!(
                    error.kind(),
                    ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
                )
            }
            _ => false,
        }
    }
}

/// Container for an active computer process
///
/// This provides an API for interacting with computer processes,
/// regardless of where the computer is located.
///
/// ## Newlines
/// Lines are terminated by the newline character '\n'. Carriage return
/// characters '\r' are treated as regular text. The end-of-file is also
/// considered a line termination, unless it is forms an empty line.
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
#[derive(Debug)]
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
                    command.iter().map(|arg| arg.as_ref().len()).sum::<usize>() + command.len(),
                );
                for string in command {
                    line.push_str(&shell_escape::unix::escape(string.as_ref().into()));
                    line.push(' ');
                }
                line.pop();
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
    /// **Block** until process terminates
    ///
    /// Returns [true] if the process ended cleanly, or [false] if it was killed
    /// by a signal or if it exited with non-zero status code
    pub fn wait(&mut self) -> Result<bool, Error> {
        // Empty the pipes to prevent deadlock
        // let _ = self.read_stdout_nonblocking();
        // let _ = self.read_stderr_nonblocking();
        // self.close_stdio()?;
        //
        match &mut self.inner {
            ProcessInner::Local(child) => {
                let status = child.wait()?;
                Ok(status.success())
            }
            ProcessInner::Remote(RemoteInner {
                channel,
                nonblocking,
                ..
            }) => {
                let _guard = guard_session_blocking(nonblocking);
                channel.send_eof()?;
                channel.wait_eof()?; // required to complete before calling wait_close
                channel.close()?;
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
        // Get another batch of data and check for newline again
        match self.read_stdout_nonblocking() {
            Ok(()) => read_line(&mut self.stdout_buffer),
            Err(error) => {
                // If EOF then return all remaining data in buffer
                if error.eof() && !self.stdout_buffer.is_empty() {
                    let data = mem::take(&mut self.stdout_buffer);
                    Ok(Some(String::from_utf8(data.into())?))
                } else {
                    Err(error)
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
        self.read_stdout_nonblocking()?;
        // Check if enough data is now available
        if self.stdout_buffer.len() >= bytes {
            Ok(Some(self.stdout_buffer.drain(..bytes).collect()))
        } else {
            Ok(None)
        }
    }
    /// Manages blocking/non-blocking behavior
    fn read_stdout_nonblocking(&mut self) -> Result<(), Error> {
        self.set_stdout_blocking(false);
        let chunk = self.stdout().and_then(read_nonblocking);
        self.set_stdout_blocking(true);
        self.stdout_buffer.append(&mut chunk?.into());
        Ok(())
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
                        if stdout_buffer.is_empty() {
                            break Err(Error::Io(ErrorKind::BrokenPipe.into()));
                        } else {
                            break Ok(String::from_utf8(stdout_buffer.into())?);
                        }
                    }
                    stdout_buffer.extend(&read_buffer[..num]);
                }
                Err(err) => {
                    // Check for end of file, return all remaining data
                    if err.kind() == ErrorKind::BrokenPipe && !stdout_buffer.is_empty() {
                        // Return all remaining data
                        break Ok(String::from_utf8(stdout_buffer.into())?);
                    }
                    break Err(err.into());
                }
            }
            // Check for newline
            if let Some(line) = read_line(&mut stdout_buffer)? {
                self.stdout_buffer = stdout_buffer; // Save remaining data in buffer
                break Ok(line);
            }
        }
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
            Ok(()) => read_line(&mut self.stderr_buffer),
            Err(error) => {
                // If EOF then return remaining content, even though it's not newline terminated
                if error.eof() && !self.stderr_buffer.is_empty() {
                    let data = mem::take(&mut self.stderr_buffer);
                    let line = Some(String::from_utf8(data.into())?);
                    Ok(line)
                } else {
                    Err(error)
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
            Err(error) => {
                if error.eof() && !self.stderr_buffer.is_empty() {
                    let data = mem::take(&mut self.stderr_buffer);
                    return Ok(data.into());
                }
                Err(error)
            }
        }
    }
    fn read_stderr_nonblocking(&mut self) -> Result<(), Error> {
        let data = match &mut self.inner {
            ProcessInner::Local(child) => {
                let Some(stderr) = child.stderr.as_mut() else {
                    return Ok(()); // stderr was forwarded
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
                let data = read_nonblocking(&mut channel.stderr());
                set_session_blocking(session, nonblocking);
                data?
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

impl fmt::Debug for RemoteInner {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let RemoteInner { nonblocking, .. } = self;
        fmt.debug_struct("RemoteInner")
            .field("session", &format_args!("ssh2::Session"))
            .field("channel", &format_args!("ssh2::Channel"))
            .field("nonblocking", nonblocking)
            .finish()
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
fn read_nonblocking(pipe: &mut dyn Read) -> Result<Vec<u8>, Error> {
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
                    let error: io::Error = ErrorKind::BrokenPipe.into();
                    return Err(error.into());
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
            Err(error) => {
                match error.kind() {
                    ErrorKind::WouldBlock => {
                        unsafe { buffer.set_len(len) };
                        return Ok(buffer);
                    }
                    _ => {
                        return Err(error.into());
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
        let inner = nonblocking.lock().unwrap();
        if *inner == 0 {
            break inner;
        } else {
            mem::drop(inner);
            thread::yield_now();
        }
    }
}

/// Forward process standard error streams in background thread
///
/// This spawns a new thread that reads stderr from processes and writes to an
/// output `io::Write` implementation. Stderr is read in non-blocking mode.
/// Each thread accepts multiple process. The background thread exits when
/// this object is dropped.
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
    /// Spawn a new thread that forwards stderr messages to the given writer
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
                            Ok(size) if size > 0 => {
                                destination.write_all(&buffer[..size]).unwrap();
                            }
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                break;
                            }
                            _ => {
                                dead.push(index); // Mark this source for removal
                                break;
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
                            match stderr.read(&mut buffer) {
                                Ok(size) if size > 0 => {
                                    destination.write_all(&buffer[..size]).unwrap();
                                }
                                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                    break;
                                }
                                _ => {
                                    dead.push(index); // Mark this source for removal
                                    break;
                                }
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
    use std::env::temp_dir;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::sync::OnceLock;

    /// Every test is evaluated on every computer
    fn computer_test_assets() -> Vec<Arc<Computer>> {
        vec![Computer::new_local(), remote_publickey_computer()]
    }

    /// Start an SSH server using public-key authentication
    fn remote_publickey_computer() -> Arc<Computer> {
        let (_server, computer) = PUBLICKEY_SERVER.get_or_init(|| {
            let mut keys = SshKeyFiles::new();
            keys.generate();
            let (server, port) = spawn_sshd_publickey_remote(&keys);
            let computer = Arc::new(Computer::Remote {
                host: String::new(),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
                user: "dm".to_string(),
                auth: String::new(),
                key: keys.client_private.clone(),
            });
            (server, computer)
        });
        computer.clone()
    }
    /// Keep the child (ssh-server) alive until end of program
    static PUBLICKEY_SERVER: OnceLock<(Child, Arc<Computer>)> = OnceLock::new();

    struct SshKeyFiles {
        base_dir: PathBuf,
        server_private: PathBuf,
        server_public: PathBuf,
        client_private: PathBuf,
        client_public: PathBuf,
    }
    impl SshKeyFiles {
        fn new() -> Self {
            let base_dir = temp_dir().join("process_anywhere_test");
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
        /// Remove all encryption key files
        fn delete(&mut self) {
            if self.server_private.exists() {
                fs::remove_file(&self.server_private).unwrap();
                fs::remove_file(&self.server_public).unwrap();
                fs::remove_file(&self.client_private).unwrap();
                fs::remove_file(&self.client_public).unwrap();
            }
        }
        /// Create new encryption keys
        fn generate(&mut self) {
            self.delete();
            for path in [&self.server_private, &self.client_private] {
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
        }
    }

    /// Get an unused port number from the OS
    fn get_free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Spawn the SSH server process
    #[cfg(target_family = "unix")]
    fn spawn_sshd_publickey_remote(keys: &SshKeyFiles) -> (Child, u16) {
        let port = get_free_port();
        let port_string = port.to_string();
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
            key: PathBuf::new(),
        };

        let debug = format!("{comp1:?}\n{comp2:?}");
        assert!(debug.contains("unit_test"));
        assert!(!debug.contains("Z"));
    }

    #[test]
    fn echo_server() {
        for comp in computer_test_assets() {
            dbg!(&comp);
            let mut proc = dbg!(comp.exec(&["cat", "-"]).unwrap());
            assert!(proc.is_alive().unwrap());

            // No data yet, should instantly yield (non-blocking).
            assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

            // Send a message. Process should echo it back to stdout.
            proc.send_line("Hello World!").unwrap();
            thread::sleep(time::Duration::from_millis(100));
            assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello World!");

            // Message consumed, no further messages.
            assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

            // Test newline handling
            proc.send_line("Hello\n\n \nlocalhost\n").unwrap();
            thread::sleep(time::Duration::from_millis(100));
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "Hello");
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "");
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), " ");
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "localhost");
            assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

            // Test shutdown procedure
            assert!(proc.error_bytes().unwrap().is_empty());
            assert!(proc.is_alive().unwrap());
            assert!(proc.wait().unwrap());
            assert!(!proc.is_alive().unwrap());
        }
    }

    #[test]
    fn error_line() {
        for comp in computer_test_assets() {
            dbg!(&comp);
            let mut proc = dbg!(
                comp.exec(&[
                    "python3",
                    "-c",
                    "import sys
print('test error_line', file=sys.stderr)
# sys.stdin.close()
# sys.stdout.close()
exit(1)"
                ])
                .unwrap()
            );
            thread::sleep(time::Duration::from_millis(500));
            // Check process is kept "alive" by buffered & uncollected data
            assert!(proc.is_alive().unwrap());
            dbg!();
            assert!(proc.recv_line().is_err());
            dbg!();
            assert!(proc.recv_bytes(1).is_err());
            dbg!();
            assert!(dbg!(proc.block_line()).is_err());
            assert!(dbg!(proc.block_bytes(1)).is_err());
            let line = dbg!(proc.error_line().unwrap()).unwrap();
            assert_eq!(line, "test error_line");
            assert!(proc.error_line().is_err());
            assert!(proc.error_bytes().is_err());
            for _ in 0..3 {
                assert!(!proc.is_alive().unwrap());
                assert!(!proc.wait().unwrap());
            }
        }
    }

    /// Check it can get the last line before an EOF
    #[test]
    fn eof_line() {
        for comp in computer_test_assets() {
            dbg!(&comp);
            let mut proc = dbg!(comp.exec(&["echo", "-e", "one\ntwo \nthree"]).unwrap());
            thread::sleep(time::Duration::from_millis(100));
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "one");
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "two ");
            assert!(proc.is_alive().unwrap());
            assert_eq!(dbg!(proc.recv_line().unwrap()).unwrap(), "three");
            assert!(dbg!(proc.recv_line()).is_err());
            assert!(!proc.is_alive().unwrap());
            assert!(proc.wait().unwrap());
        }
    }

    #[test]
    fn is_alive() {
        for comp in computer_test_assets() {
            dbg!(&comp);
            let mut proc = dbg!(comp.exec(&["sleep", ".5"]).unwrap());
            // Check that stderr forwarding does not interfere with blocking/non-blocking
            let fwd = Forwarder::new(Box::new(io::stderr()));
            fwd.forward_stderr(&mut proc).unwrap();
            thread::sleep(time::Duration::from_millis(100));
            // Poll the sleeping process's status
            for _ in 0..100 {
                assert!(proc.is_alive().unwrap());
            }
            // Close stdio, should not affect process
            proc.close_stdio().unwrap();
            thread::sleep(time::Duration::from_millis(100));
            for _ in 0..100 {
                assert!(proc.is_alive().unwrap());
            }
            // Check repeated calls to wait() & is_alive() yield consistent results after death
            for _ in 0..10 {
                assert!(proc.wait().unwrap());
                assert!(!proc.is_alive().unwrap());
            }
            assert!(!proc.is_alive().unwrap());
        }
    }

    /// Test sending and receiving files.
    #[test]
    #[ignore]
    fn file_roundtrip() {
        // This testcase does not work. The problem is that there is only one
        // file system, and send & recv files only accepts one file-path,
        // which serves as both source and destination. Therefore it's
        // impossible to send/recv files with localhost w/o overwriting.
        // This might be a bit of an API flaw...

        // Make a new local directory.
        let dir_name = temp_dir().join("process_anywhere_file_roundtrip");
        fs::create_dir_all(&dir_name).unwrap();

        // Make a new local file.
        let file_name = dir_name.join("test_file");
        let file_data = "Hello roundtrip!";
        fs::write(&file_name, &file_data).unwrap();

        // Send it to the remote test computer.
        let comp = remote_publickey_computer();
        comp.send_file(&file_name).unwrap();

        // Delete the local copy of the file & directory.
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
    fn forwarder() {
        let log_file = temp_dir().join("process_anywhere_stderr_test");
        if log_file.exists() {
            fs::remove_file(&log_file).unwrap();
        }
        let log = fs::File::create(&log_file).unwrap();
        let fwd = Forwarder::new(Box::new(log));
        const EPRINT: &str = "import sys; print('TEST', file=sys.stderr, flush=True);";
        const SLEEP: &str = "import time; time.sleep(1);";
        let prog1 = format!("{EPRINT}{SLEEP}");
        let prog2 = format!("{SLEEP}{EPRINT}");
        // Run prog1 on all computers
        let mut proc1 = vec![];
        for comp in computer_test_assets() {
            let mut proc = comp.clone().exec(&["python3", "-c", &prog1]).unwrap();
            fwd.forward_stderr(&mut proc).unwrap();
            proc1.push(proc);
        }
        //
        thread::sleep(time::Duration::from_millis(500));
        // Check that processes can be added to the forwarder at any time
        let mut proc2 = vec![];
        for comp in computer_test_assets() {
            let mut proc = comp.clone().exec(&["python3", "-c", &prog2]).unwrap();
            fwd.forward_stderr(&mut proc).unwrap();
            proc2.push(proc);
        }
        let mut proc3 = vec![];
        for comp in computer_test_assets() {
            let mut proc = comp.clone().exec(&["python3", "-c", &prog2]).unwrap();
            proc.close_stdio().unwrap(); // test forward stderr w/ closed stdin & stdout
            fwd.forward_stderr(&mut proc).unwrap();
            proc3.push(proc)
        }
        // Check forwarder remains active for proc2 and proc3 after proc1 terminates
        for proc in &mut proc1 {
            assert!(proc.wait().unwrap());
            assert!(!proc.is_alive().unwrap());
        }
        for proc in &mut proc2 {
            assert!(proc.is_alive().unwrap());
        }
        for proc in &mut proc3 {
            assert!(proc.is_alive().unwrap());
        }
        // Wait for all processes to exit
        for proc in &mut proc2 {
            assert!(proc.wait().unwrap());
        }
        for proc in &mut proc3 {
            assert!(proc.wait().unwrap());
        }
        // Wait and check that forwarder collected remaining data
        thread::sleep(time::Duration::from_millis(500));
        for proc in &mut proc2 {
            assert!(!proc.is_alive().unwrap());
        }
        for proc in &mut proc3 {
            assert!(!proc.is_alive().unwrap());
        }
        // Check the stderr log
        mem::drop(fwd);
        let stderr_log = fs::read(log_file).unwrap();
        let stderr_log = String::from_utf8(stderr_log).unwrap();
        dbg!(&stderr_log);
        let lines: Vec<&str> = stderr_log.lines().collect();
        assert!(lines.len() == 3 * proc1.len());
        assert!(lines.iter().all(|x| *x == "TEST"));
    }

    // Check all blocking calls, and check that forwarder does not interfere
    #[test]
    fn blocking() {
        const PROGRAM: &str = "import sys; import time;
time.sleep(1)
print('hello', flush=True)
sys.stdout.buffer.write(b'world!')
sys.stdout.flush()
exit(0)";
        let mut processes: Vec<Box<Process>> = computer_test_assets()
            .iter()
            .map(|comp| comp.clone().exec(&["python3", "-c", PROGRAM]).unwrap())
            .collect();
        //
        let fwd = Forwarder::new(Box::new(io::stderr()));
        for proc in &mut processes {
            fwd.forward_stderr(proc).unwrap();
        }
        thread::sleep(time::Duration::from_millis(500));
        // Check non-blocking before results are ready.
        for proc in &mut processes {
            for _ in 0..1000 {
                assert!(proc.recv_line().unwrap().is_none());
                assert!(proc.recv_bytes(1).unwrap().is_none());
                assert!(proc.recv_bytes(0).unwrap() == Some(Box::new([])));
            }
        }
        // Wait for results.
        for proc in &mut processes {
            assert_eq!(proc.block_line().unwrap(), "hello");
            assert_eq!(proc.block_bytes(6).unwrap(), (*b"world!").into());
            assert!(proc.wait().unwrap());
            assert!(!proc.is_alive().unwrap());
            // Check all call now yield EOF
            assert!(proc.recv_line().unwrap_err().eof());
            assert!(proc.recv_bytes(1).unwrap_err().eof());
            assert!(proc.block_line().unwrap_err().eof());
            assert!(proc.block_bytes(1).unwrap_err().eof());
        }
    }
}
