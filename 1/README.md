# POSIX Low-Level File Transfer Utility (`sys_transfer`)

A production-grade, low-level C++ file transfer utility engineered strictly with raw Linux system calls (`open`, `read`, `write`, `close`, `stat`, `access`, `realpath`, `fchmod`, `fsync`, `unlink`).

Designed for Operating Systems & Linux Kernel architecture courses with **zero reliance** on high-level I/O abstractions (`<iostream>`, `<fstream>`, `<stdio.h>`, `std::filesystem`, or Boost).

---

## 1. Architectural Highlights & System Call Lifecycle

```
[Source Path]
      │
      ▼
┌──────────────┐
│  access()    │ ──► Verify read access & file existence
└──────────────┘
      │
      ▼
┌──────────────┐
│  realpath()  │ ──► Resolve canonical absolute path
└──────────────┘
      │
      ▼
┌──────────────┐
│   stat()     │ ──► Validate regular file (!S_ISDIR), extract inode, dev, mode
└──────────────┘
      │
      ▼
┌──────────────┐
│  Same-File   │ ──► Compare (st_dev, st_ino) to prevent self-truncation
│    Check     │
└──────────────┘
      │
      ▼
┌──────────────┐
│   open()     │ ──► O_RDONLY | O_CLOEXEC (Source)
│   open()     │ ──► O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC (Dest)
└──────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│ Chunked Read/Write Loop (64 KiB Page-Aligned Buffer)   │
│   ┌────────────────────────────────────────────────┐   │
│   │ read(src_fd, buffer, 64KB)                     │   │
│   │   - Retry on EINTR                             │   │
│   │   - Break on EOF (0)                           │   │
│   └────────────────────────────────────────────────┘   │
│                          │                             │
│                          ▼                             │
│   ┌────────────────────────────────────────────────┐   │
│   │ write(dest_fd, buffer + offset, remaining)     │   │
│   │   - Retry on EINTR                             │   │
│   │   - Handle Partial / Short Writes              │   │
│   └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────┐
│  fchmod()    │ ──► Enforce exact permissions (bypassing process umask)
└──────────────┘
      │
      ▼
┌──────────────┐
│   fsync()    │ ──► Flush dirty pages from OS page cache to disk
└──────────────┘
      │
      ▼
┌──────────────┐
│   close()    │ ──► Close file descriptors & check return status
└──────────────┘
      │
      ▼
┌──────────────┐
│   unlink()   │ ──► (If --move): Safely remove source after verified copy
└──────────────┘
```

---

## 2. In-Depth Technical & Kernel Details

### A. Why No `<stdio.h>` or `<iostream>`?
Higher-level libraries introduce runtime overhead, internal buffering (e.g., standard C stream buffers), locale conversions, and text-mode translations. This utility interacts directly with the Linux VFS (Virtual Filesystem Switch) using unbuffered POSIX system calls. All diagnostic outputs and errors are written via raw `write(STDOUT_FILENO, ...)` and `write(STDERR_FILENO, ...)`.

### B. Handling Partial Writes and `EINTR`
- **Short Writes:** The POSIX standard allows `write()` to commit fewer bytes than requested (e.g., when under kernel memory pressure or writing across storage boundaries). A naive single `write()` call would result in silent data corruption. Our nested write loop tracks `total_written` and loops until `total_written == bytes_read`.
- **Signal Interruption (`EINTR`):** If an asynchronous signal arrives while a process is blocked in `read()` or `write()`, the kernel returns `-1` with `errno == EINTR`. Inspecting `errno` and executing `continue` guarantees transfer resilience.

### C. Permissions Preservation & The `umask` Problem
When `open(..., O_CREAT, mode)` creates a file, the resulting file mode is altered by the process `umask`:
$$\text{Created Mode} = \text{mode} \ \& \ \sim\text{umask}$$
To ensure bit-for-bit permission fidelity (including execution flags `0755` or restricted modes `0600`), the engine immediately issues `fchmod(dest_fd, src_stat.st_mode & 07777)`, explicitly restoring the original mode.

### D. Data Durability via `fsync()`
Writing to a file descriptor copies data into the Linux kernel page cache. Calling `fsync(dest_fd)` commands the storage controller to commit all dirty pages and metadata to persistent non-volatile storage. In `--move` mode, this ensures data integrity before the source directory entry is severed via `unlink()`.

### E. Self-Overwrite Detection
If the user specifies `./sys_transfer file.bin file.bin` or links pointing to the same file, opening the destination with `O_TRUNC` would immediately erase the source before the first `read()`. Comparing `src_stat.st_dev == dest_stat.st_dev && src_stat.st_ino == dest_stat.st_ino` safely identifies and aborts this condition.

---

## 3. Compilation Guide

### Standard Compilation with strict GNU flags:
```bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -O2 sys_transfer.cpp -o sys_transfer
```

### Or using the provided `Makefile`:
```bash
make
```

### Running the automated verification suite:
```bash
make test
```

---

## 4. Usage & Command Reference

```bash
./sys_transfer [OPTIONS] <source_file> <destination>
```

### Supported Options:
- `-m`, `--move`: Safely move the file (complete copy, byte verification, `fsync`, followed by `unlink` of the original).
- `-v`, `--verbose`: Display full inode, device ID, permission mode, and block metadata.
- `-h`, `--help`: Display usage syntax.

---

## 5. Sample Commands for Binary & Arbitrary Data

### 1. Copying a PDF Document
```bash
./sys_transfer lecture_notes.pdf /tmp/lecture_notes_backup.pdf
```

### 2. Copying an Audio File (.wav / .mp3) to a Target Directory
```bash
./sys_transfer track01.wav ~/Music/
# Automatically resolves to ~/Music/track01.wav
```

### 3. Transferring an Image (.png / .jpg) in Move Mode
```bash
./sys_transfer --move diagram.png ~/archive/diagram.png
```

### 4. Copying an Executable / Disk Image (.iso / ELF)
```bash
./sys_transfer /bin/bash ./bash_copy
# Verifies that execute permissions (e.g. 0755) are strictly retained
```
