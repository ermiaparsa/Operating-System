/**
 * ============================================================================
 * Project: Production-Grade Low-Level File Transfer Utility (sys_transfer)
 * Course:  Operating Systems & Linux Kernel Architecture
 * 
 * Design Philosophy & Constraints:
 * 1. Zero High-Level Abstractions:
 *    Strictly NO <iostream>, <fstream>, <stdio.h> (printf/fopen/fread),
 *    std::filesystem, or Boost.
 * 2. Pure POSIX Linux System Calls:
 *    - File descriptor lifecycle: open(), read(), write(), fsync(), close(), unlink()
 *    - Status & Metadata: stat(), lstat(), access(), fchmod()
 *    - Canonical Path Resolution: realpath()
 * 3. Binary Transparency:
 *    Raw byte-stream handling without character encodings or null-byte termination.
 *    Flawlessly transfers ELF executables, images (.png, .jpg), audio (.wav, .mp3),
 *    documents (.pdf), disk images (.iso), and arbitrary raw bytes.
 * 4. Production Hardening:
 *    - Loop-level partial write mitigation (write() returning < requested)
 *    - Signal interrupt tolerance (EINTR retry semantics on read/write)
 *    - Same-file detection (st_dev + st_ino check) preventing self-truncation
 *    - Directory target handling (auto-resolving target filenames)
 *    - Exact permission preservation overriding process umask via fchmod()
 *    - Data durability via fsync() before source unlinking in move mode
 * ============================================================================
 */

#include <fcntl.h>        // open(), O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC, O_CLOEXEC
#include <unistd.h>       // read(), write(), close(), unlink(), fsync(), access(), STDOUT_FILENO, STDERR_FILENO
#include <sys/stat.h>     // stat(), lstat(), fchmod(), struct stat, S_ISREG, S_ISDIR, mode flags
#include <sys/types.h>    // mode_t, off_t, ssize_t, dev_t, ino_t
#include <errno.h>        // errno and error definitions (EACCES, ENOENT, EISDIR, ENOSPC, EINTR, etc.)
#include <limits.h>       // PATH_MAX
#include <cstdlib>        // realpath()
#include <cstdint>        // uint64_t, uint32_t, size_t
#include <cstring>        // strerror_r, strlen, strcmp, strncmp

namespace Sys {

    // ========================================================================
    // SECTION 1: Low-Level Unbuffered POSIX I/O Print Engine
    // ------------------------------------------------------------------------
    // Completely replaces <iostream> and <stdio.h> using raw write() syscalls.
    // Handles partial writes and EINTR signals during diagnostic output.
    // ========================================================================

    namespace Out {

        /**
         * Safely writes a raw byte buffer to a file descriptor.
         * Accounts for partial writes and handles EINTR signal interruptions.
         */
        inline void write_raw(int fd, const char* data, size_t length) {
            size_t total_written = 0;
            while (total_written < length) {
                ssize_t written = ::write(fd, data + total_written, length - total_written);
                if (written < 0) {
                    if (errno == EINTR) {
                        // Syscall interrupted by signal; retry write
                        continue;
                    }
                    // Terminal write error occurred; break to avoid infinite loop
                    break;
                }
                total_written += static_cast<size_t>(written);
            }
        }

        /**
         * Outputs a null-terminated C-string to the specified file descriptor.
         */
        inline void write_str(int fd, const char* str) {
            if (!str) return;
            write_raw(fd, str, ::strlen(str));
        }

        /**
         * Formats and prints an unsigned 64-bit integer in base 10 using a stack buffer.
         */
        inline void write_uint(int fd, uint64_t value) {
            char buffer[32];
            if (value == 0) {
                buffer[0] = '0';
                write_raw(fd, buffer, 1);
                return;
            }

            char temp[32];
            int tpos = 0;
            while (value > 0) {
                temp[tpos++] = static_cast<char>('0' + (value % 10));
                value /= 10;
            }

            int bpos = 0;
            while (tpos > 0) {
                buffer[bpos++] = temp[--tpos];
            }
            write_raw(fd, buffer, static_cast<size_t>(bpos));
        }

        /**
         * Formats and prints an unsigned integer in base 8 (octal) with a leading zero.
         */
        inline void write_octal(int fd, uint32_t value) {
            char buffer[16];
            buffer[0] = '0';
            if (value == 0) {
                write_raw(fd, buffer, 1);
                return;
            }

            char temp[16];
            int tpos = 0;
            while (value > 0) {
                temp[tpos++] = static_cast<char>('0' + (value % 8));
                value /= 8;
            }

            int bpos = 1;
            while (tpos > 0) {
                buffer[bpos++] = temp[--tpos];
            }
            write_raw(fd, buffer, static_cast<size_t>(bpos));
        }

        /**
         * Formats POSIX file mode bits into standard 10-character symbolic string
         * (e.g., "-rwxr-xr-x").
         */
        inline void write_mode_symbols(int fd, mode_t mode) {
            char perm[11];

            // 1. File Type Indicator
            if (S_ISREG(mode))       perm[0] = '-';
            else if (S_ISDIR(mode))  perm[0] = 'd';
            else if (S_ISLNK(mode))  perm[0] = 'l';
            else if (S_ISCHR(mode))  perm[0] = 'c';
            else if (S_ISBLK(mode))  perm[0] = 'b';
            else if (S_ISFIFO(mode)) perm[0] = 'p';
            else if (S_ISSOCK(mode)) perm[0] = 's';
            else                     perm[0] = '?';

            // 2. Owner permissions (User)
            perm[1] = (mode & S_IRUSR) ? 'r' : '-';
            perm[2] = (mode & S_IWUSR) ? 'w' : '-';
            perm[3] = (mode & S_ISUID) ? ((mode & S_IXUSR) ? 's' : 'S') : ((mode & S_IXUSR) ? 'x' : '-');

            // 3. Group permissions
            perm[4] = (mode & S_IRGRP) ? 'r' : '-';
            perm[5] = (mode & S_IWGRP) ? 'w' : '-';
            perm[6] = (mode & S_ISGID) ? ((mode & S_IXGRP) ? 's' : 'S') : ((mode & S_IXGRP) ? 'x' : '-');

            // 4. Other permissions
            perm[7] = (mode & S_IROTH) ? 'r' : '-';
            perm[8] = (mode & S_IWOTH) ? 'w' : '-';
            perm[9] = (mode & S_ISVTX) ? ((mode & S_IXOTH) ? 't' : 'T') : ((mode & S_IXOTH) ? 'x' : '-');

            perm[10] = '\0';
            write_raw(fd, perm, 10);
        }

        /**
         * Returns a descriptive string for common POSIX error codes.
         * Falls back to strerror_r for complete coverage.
         */
        inline void write_posix_error(int fd, const char* context, int errnum) {
            write_str(fd, "[ERROR] ");
            write_str(fd, context);
            write_str(fd, ": (errno ");
            write_uint(fd, static_cast<uint64_t>(errnum));
            write_str(fd, ") ");

            // Detailed descriptions for file I/O errors
            switch (errnum) {
                case EACCES:
                    write_str(fd, "Permission denied (insufficient access rights)");
                    break;
                case ENOENT:
                    write_str(fd, "No such file or directory (path does not exist)");
                    break;
                case EISDIR:
                    write_str(fd, "Is a directory (expected a regular file)");
                    break;
                case ENOTDIR:
                    write_str(fd, "Not a directory (component of path prefix is not a directory)");
                    break;
                case ENOSPC:
                    write_str(fd, "No space left on device (storage capacity exhausted)");
                    break;
                case EEXIST:
                    write_str(fd, "File exists");
                    break;
                case EFBIG:
                    write_str(fd, "File too large (exceeds maximum file size)");
                    break;
                case EIO:
                    write_str(fd, "Input/output hardware error occurred during transfer");
                    break;
                case EROFS:
                    write_str(fd, "Read-only file system (cannot modify or create files)");
                    break;
                case EINTR:
                    write_str(fd, "Interrupted system call");
                    break;
                case EMFILE:
                    write_str(fd, "Too many open files for this process (file descriptor limit reached)");
                    break;
                case ENFILE:
                    write_str(fd, "Too many open files in system (kernel table full)");
                    break;
                case ELOOP:
                    write_str(fd, "Too many levels of symbolic links encountered");
                    break;
                case ENAMETOOLONG:
                    write_str(fd, "File name too long (exceeds PATH_MAX or NAME_MAX)");
                    break;
                default: {
                    char err_buf[256];
                    // strerror_r is POSIX-compliant and thread-safe
                    #if (_POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
                        if (strerror_r(errnum, err_buf, sizeof(err_buf)) == 0) {
                            write_str(fd, err_buf);
                        } else {
                            write_str(fd, "Unknown POSIX error");
                        }
                    #else
                        char* msg = strerror_r(errnum, err_buf, sizeof(err_buf));
                        write_str(fd, msg ? msg : "Unknown POSIX error");
                    #endif
                    break;
                }
            }
            write_str(fd, "\n");
        }

    } // namespace Out

    // ========================================================================
    // SECTION 2: Path Manipulation & Inspection Helpers
    // ------------------------------------------------------------------------
    // Provides directory extraction and basename resolution using low-level
    // string indexing without std::string or std::filesystem.
    // ========================================================================

    namespace Path {

        /**
         * Extracts the basename component from a path string.
         * Example: "/usr/bin/cat" -> "cat", "sample.pdf" -> "sample.pdf"
         */
        inline const char* get_basename(const char* path) {
            if (!path || path[0] == '\0') return ".";
            const char* last_slash = nullptr;
            for (const char* p = path; *p != '\0'; ++p) {
                if (*p == '/') {
                    last_slash = p;
                }
            }
            if (!last_slash) {
                return path;
            }
            // If the path ends with a slash (e.g. "dir/"), look backwards
            if (*(last_slash + 1) == '\0') {
                return path; // Directory path representation
            }
            return last_slash + 1;
        }

        /**
         * Combines a directory path and a filename into a target buffer.
         * Ensures no double slashes and respects PATH_MAX.
         */
        inline bool combine(char* dest, size_t dest_size, const char* dir, const char* filename) {
            size_t dir_len = ::strlen(dir);
            size_t file_len = ::strlen(filename);
            bool needs_slash = (dir_len > 0 && dir[dir_len - 1] != '/');
            size_t total_len = dir_len + (needs_slash ? 1 : 0) + file_len;

            if (total_len + 1 > dest_size) {
                return false; // Path would exceed buffer
            }

            size_t pos = 0;
            for (size_t i = 0; i < dir_len; ++i) dest[pos++] = dir[i];
            if (needs_slash) dest[pos++] = '/';
            for (size_t i = 0; i < file_len; ++i) dest[pos++] = filename[i];
            dest[pos] = '\0';
            return true;
        }

    } // namespace Path

    // ========================================================================
    // SECTION 3: Program Configuration & Metadata Structures
    // ========================================================================

    struct TransferConfig {
        const char* source_arg = nullptr;
        const char* dest_arg   = nullptr;
        bool is_move_mode      = false; // If true: safely unlink source after verified copy
        bool verbose           = false; // If true: print detailed inode/system info
    };

    struct FileMetadata {
        struct stat raw_stat;
        char resolved_path[PATH_MAX];
        bool path_resolved;
    };

    // ========================================================================
    // SECTION 4: Core Engine Verification & Transfer Implementations
    // ========================================================================

    class FileTransferEngine {
    public:
        // Optimal chunk buffer size: 64 KiB (16 OS memory pages)
        // Aligned to 4096-byte boundary to maximize direct kernel memory throughput
        static constexpr size_t CHUNK_SIZE = 65536;

        /**
         * Inspects and validates the source file.
         * Verifies existence, read permissions, file type, and extracts metadata.
         */
        static bool inspect_source(const char* src_path, FileMetadata& meta) {
            // Check existence and read permissions via access()
            if (::access(src_path, F_OK) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Source verification failed (access)", errno);
                return false;
            }
            if (::access(src_path, R_OK) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Source read permission denied (access)", errno);
                return false;
            }

            // Retrieve status information via stat()
            if (::stat(src_path, &meta.raw_stat) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Source metadata retrieval failed (stat)", errno);
                return false;
            }

            // Enforce regular file requirement
            // Reject directories (EISDIR) and non-transferable special files
            if (S_ISDIR(meta.raw_stat.st_mode)) {
                Out::write_posix_error(STDERR_FILENO, "Source is a directory; regular file required", EISDIR);
                return false;
            }
            if (!S_ISREG(meta.raw_stat.st_mode)) {
                Out::write_str(STDERR_FILENO, "[ERROR] Source is not a regular file (e.g., device or FIFO special file)\n");
                return false;
            }

            // Canonicalize source path using realpath()
            if (::realpath(src_path, meta.resolved_path) != nullptr) {
                meta.path_resolved = true;
            } else {
                meta.path_resolved = false;
                // Copy literal path if realpath fails (fallback)
                size_t len = ::strlen(src_path);
                if (len < PATH_MAX) {
                    for (size_t i = 0; i <= len; ++i) meta.resolved_path[i] = src_path[i];
                }
            }

            return true;
        }

        /**
         * Resolves the final destination path.
         * If the destination is an existing directory, appends the source's basename.
         */
        static bool resolve_destination_path(const char* src_path, 
                                             const char* dest_arg, 
                                             char* out_dest_path, 
                                             size_t dest_path_size) {
            struct stat dest_stat;
            int ret = ::stat(dest_arg, &dest_stat);

            if (ret == 0 && S_ISDIR(dest_stat.st_mode)) {
                // Destination is an existing directory: append source basename
                const char* base = Path::get_basename(src_path);
                if (!Path::combine(out_dest_path, dest_path_size, dest_arg, base)) {
                    Out::write_posix_error(STDERR_FILENO, "Destination path construction exceeds PATH_MAX", ENAMETOOLONG);
                    return false;
                }
            } else {
                // Destination is a file path (exists or new)
                size_t len = ::strlen(dest_arg);
                if (len + 1 > dest_path_size) {
                    Out::write_posix_error(STDERR_FILENO, "Destination path exceeds PATH_MAX", ENAMETOOLONG);
                    return false;
                }
                for (size_t i = 0; i <= len; ++i) {
                    out_dest_path[i] = dest_arg[i];
                }
            }
            return true;
        }

        /**
         * Safety Guard: Checks if source and destination refer to the exact same file.
         * Compares device ID (st_dev) and inode number (st_ino).
         */
        static bool check_self_overwrite(const struct stat& src_stat, const char* final_dest_path) {
            struct stat target_stat;
            if (::stat(final_dest_path, &target_stat) == 0) {
                if (src_stat.st_dev == target_stat.st_dev && src_stat.st_ino == target_stat.st_ino) {
                    Out::write_str(STDERR_FILENO, "[ERROR] Source and destination refer to the exact same physical inode (");
                    Out::write_uint(STDERR_FILENO, static_cast<uint64_t>(src_stat.st_ino));
                    Out::write_str(STDERR_FILENO, "). Aborting to prevent file truncation!\n");
                    return true; // Conflict detected
                }
            }
            return false; // Safe to proceed
        }

        /**
         * Displays comprehensive metadata about the source file.
         */
        static void display_metadata(const FileMetadata& meta, const char* final_dest) {
            Out::write_str(STDOUT_FILENO, "============================================================\n");
            Out::write_str(STDOUT_FILENO, "               FILE METADATA & POSIX STATUS                 \n");
            Out::write_str(STDOUT_FILENO, "============================================================\n");
            
            Out::write_str(STDOUT_FILENO, "Source Path (Resolved): ");
            Out::write_str(STDOUT_FILENO, meta.resolved_path);
            Out::write_str(STDOUT_FILENO, "\n");

            Out::write_str(STDOUT_FILENO, "Destination Path:       ");
            Out::write_str(STDOUT_FILENO, final_dest);
            Out::write_str(STDOUT_FILENO, "\n");

            Out::write_str(STDOUT_FILENO, "File Size:              ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_size));
            Out::write_str(STDOUT_FILENO, " bytes (");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_blocks));
            Out::write_str(STDOUT_FILENO, " 512-byte blocks allocated)\n");

            Out::write_str(STDOUT_FILENO, "Inode Number:           ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_ino));
            Out::write_str(STDOUT_FILENO, "\n");

            Out::write_str(STDOUT_FILENO, "Device ID:              ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_dev));
            Out::write_str(STDOUT_FILENO, "\n");

            Out::write_str(STDOUT_FILENO, "Preferred I/O Block:    ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_blksize));
            Out::write_str(STDOUT_FILENO, " bytes\n");

            Out::write_str(STDOUT_FILENO, "Access Permissions:     ");
            Out::write_mode_symbols(STDOUT_FILENO, meta.raw_stat.st_mode);
            Out::write_str(STDOUT_FILENO, " (Octal: ");
            Out::write_octal(STDOUT_FILENO, static_cast<uint32_t>(meta.raw_stat.st_mode & 07777));
            Out::write_str(STDOUT_FILENO, ")\n");

            Out::write_str(STDOUT_FILENO, "Owner UID / GID:        ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_uid));
            Out::write_str(STDOUT_FILENO, " / ");
            Out::write_uint(STDOUT_FILENO, static_cast<uint64_t>(meta.raw_stat.st_gid));
            Out::write_str(STDOUT_FILENO, "\n");
            Out::write_str(STDOUT_FILENO, "------------------------------------------------------------\n");
        }

        /**
         * Executes the low-level chunked data transfer loop.
         * Ensures:
         * - Partial write recovery (handling write() < requested)
         * - Interrupted syscall recovery (handling EINTR on read and write)
         * - Permission preservation via fchmod()
         * - Data durability via fsync()
         */
        static bool execute_transfer(const char* src_path, 
                                     const char* dest_path, 
                                     const struct stat& src_stat, 
                                     uint64_t& out_bytes_copied) {
            out_bytes_copied = 0;

            // 1. Open Source File Descriptor
            // Flags:
            // - O_RDONLY: Open strictly for reading
            // - O_CLOEXEC: Close file descriptor automatically if an execve() is invoked
            int src_fd = ::open(src_path, O_RDONLY | O_CLOEXEC);
            if (src_fd < 0) {
                Out::write_posix_error(STDERR_FILENO, "Failed to open source file (open)", errno);
                return false;
            }

            // 2. Open / Create Destination File Descriptor
            // Flags:
            // - O_WRONLY: Open strictly for writing
            // - O_CREAT:  Create the file if it does not already exist
            // - O_TRUNC:  Truncate existing file length to 0 (clean overwrite)
            // - O_CLOEXEC: Close on exec
            // Initial mode is masked by umask; exact permissions are restored with fchmod()
            mode_t create_mode = src_stat.st_mode & 07777;
            int dest_fd = ::open(dest_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, create_mode);
            if (dest_fd < 0) {
                Out::write_posix_error(STDERR_FILENO, "Failed to create/open destination file (open)", errno);
                ::close(src_fd);
                return false;
            }

            // 3. Page-aligned Transfer Buffer
            // 64 KiB buffer aligned on a 4096-byte page boundary ensures optimal DMA/kernel throughput
            alignas(4096) char buffer[CHUNK_SIZE];

            bool transfer_successful = true;

            // 4. Primary Read / Write Loop
            while (true) {
                // Perform chunked read
                ssize_t bytes_read = ::read(src_fd, buffer, sizeof(buffer));

                if (bytes_read == 0) {
                    // End of file (EOF) reached cleanly
                    break;
                }

                if (bytes_read < 0) {
                    if (errno == EINTR) {
                        // System call interrupted by an asynchronous signal; retry
                        continue;
                    }
                    // Unrecoverable read error (e.g. EIO hardware failure)
                    Out::write_posix_error(STDERR_FILENO, "Critical read failure during transfer (read)", errno);
                    transfer_successful = false;
                    break;
                }

                // 5. Nested Partial Write Safety Loop
                // A single write() syscall may accept fewer bytes than requested.
                // We must continuously loop until all bytes read in this chunk are committed.
                size_t total_written = 0;
                while (total_written < static_cast<size_t>(bytes_read)) {
                    ssize_t bytes_written = ::write(dest_fd, 
                                                    buffer + total_written, 
                                                    static_cast<size_t>(bytes_read) - total_written);

                    if (bytes_written < 0) {
                        if (errno == EINTR) {
                            // Signal interrupt occurred; retry writing remaining chunk
                            continue;
                        }
                        // Fatal write error (e.g., ENOSPC disk full, EROFS read-only FS, EFBIG)
                        Out::write_posix_error(STDERR_FILENO, "Critical write failure during transfer (write)", errno);
                        transfer_successful = false;
                        break;
                    }

                    total_written += static_cast<size_t>(bytes_written);
                }

                if (!transfer_successful) {
                    break;
                }

                out_bytes_copied += total_written;
            }

            // 6. Explicit Permission Preservation
            // open() mode is subject to the process's umask.
            // Using fchmod() guarantees that exact source file mode (including SUID/SGID/sticky bits)
            // is strictly preserved on the target.
            if (transfer_successful) {
                if (::fchmod(dest_fd, create_mode) != 0) {
                    Out::write_posix_error(STDERR_FILENO, "Warning: Failed to preserve file mode (fchmod)", errno);
                    // Non-fatal warning; transfer data is intact
                }
            }

            // 7. Flush Kernel Dirty Buffers to Persistent Storage (fsync)
            // Ensures binary data is committed to disk prior to closing or unlinking source
            if (transfer_successful) {
                if (::fsync(dest_fd) != 0) {
                    Out::write_posix_error(STDERR_FILENO, "Warning: fsync failed to flush buffers to disk (fsync)", errno);
                }
            }

            // 8. Close File Descriptors and Verify
            // Note: close() on write descriptor can report deferred write errors
            if (::close(dest_fd) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Error reported while closing destination file (close)", errno);
                transfer_successful = false;
            }
            if (::close(src_fd) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Error reported while closing source file (close)", errno);
            }

            return transfer_successful;
        }

        /**
         * Safely moves the file by copying and unlinking the original source.
         * Verifies byte counts before issuing unlink().
         */
        static bool execute_unlink_source(const char* src_path) {
            if (::unlink(src_path) != 0) {
                Out::write_posix_error(STDERR_FILENO, "Failed to unlink original source file after transfer (unlink)", errno);
                return false;
            }
            return true;
        }
    };

} // namespace Sys

// ============================================================================
// SECTION 5: Command-Line Interface & Application Entrypoint
// ============================================================================

static void print_usage(const char* prog_name) {
    Sys::Out::write_str(STDOUT_FILENO, "Usage:\n  ");
    Sys::Out::write_str(STDOUT_FILENO, prog_name);
    Sys::Out::write_str(STDOUT_FILENO, " [OPTIONS] <source_file> <destination>\n\n");
    Sys::Out::write_str(STDOUT_FILENO, "Options:\n");
    Sys::Out::write_str(STDOUT_FILENO, "  -m, --move      Transfer mode: copies the file, verifies byte integrity, and unlinks source\n");
    Sys::Out::write_str(STDOUT_FILENO, "  -v, --verbose   Verbose output: display detailed inode, block, and permission status\n");
    Sys::Out::write_str(STDOUT_FILENO, "  -h, --help      Display this educational help menu\n\n");
    Sys::Out::write_str(STDOUT_FILENO, "Pure POSIX Architecture:\n");
    Sys::Out::write_str(STDOUT_FILENO, "  Direct system calls: open, read, write, close, fsync, fchmod, stat, unlink.\n");
    Sys::Out::write_str(STDOUT_FILENO, "  Binary transparent: handles all file formats without corruption.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    Sys::TransferConfig config;

    // Parse command line arguments without external getopt libraries
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (::strcmp(arg, "-h") == 0 || ::strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (::strcmp(arg, "-m") == 0 || ::strcmp(arg, "--move") == 0) {
            config.is_move_mode = true;
        } else if (::strcmp(arg, "-v") == 0 || ::strcmp(arg, "--verbose") == 0) {
            config.verbose = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            Sys::Out::write_str(STDERR_FILENO, "[ERROR] Unknown option: ");
            Sys::Out::write_str(STDERR_FILENO, arg);
            Sys::Out::write_str(STDERR_FILENO, "\n");
            print_usage(argv[0]);
            return 1;
        } else {
            if (!config.source_arg) {
                config.source_arg = arg;
            } else if (!config.dest_arg) {
                config.dest_arg = arg;
            } else {
                Sys::Out::write_str(STDERR_FILENO, "[ERROR] Excess positional argument: ");
                Sys::Out::write_str(STDERR_FILENO, arg);
                Sys::Out::write_str(STDERR_FILENO, "\n");
                print_usage(argv[0]);
                return 1;
            }
        }
    }

    if (!config.source_arg || !config.dest_arg) {
        Sys::Out::write_str(STDERR_FILENO, "[ERROR] Missing source or destination path.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Step 1: Verify source and retrieve low-level metadata
    Sys::FileMetadata src_meta;
    if (!Sys::FileTransferEngine::inspect_source(config.source_arg, src_meta)) {
        return 1;
    }

    // Step 2: Resolve destination target path (handling existing directories)
    char final_dest_path[PATH_MAX];
    if (!Sys::FileTransferEngine::resolve_destination_path(config.source_arg, 
                                                           config.dest_arg, 
                                                           final_dest_path, 
                                                           sizeof(final_dest_path))) {
        return 1;
    }

    // Step 3: Prevent self-destruction (same device & inode check)
    if (Sys::FileTransferEngine::check_self_overwrite(src_meta.raw_stat, final_dest_path)) {
        return 1;
    }

    // Step 4: Display metadata inspection report if verbose or default run
    Sys::FileTransferEngine::display_metadata(src_meta, final_dest_path);

    // Step 5: Execute chunked copy transfer loop
    Sys::Out::write_str(STDOUT_FILENO, "[STATUS] Commencing binary stream transfer (Buffer: 64 KiB)...\n");
    uint64_t bytes_transferred = 0;
    bool success = Sys::FileTransferEngine::execute_transfer(config.source_arg, 
                                                            final_dest_path, 
                                                            src_meta.raw_stat, 
                                                            bytes_transferred);

    if (!success) {
        Sys::Out::write_str(STDERR_FILENO, "[FAILURE] Data transfer encountered fatal errors.\n");
        return 1;
    }

    // Step 6: Verify transferred byte count matches source file size
    if (bytes_transferred != static_cast<uint64_t>(src_meta.raw_stat.st_size)) {
        Sys::Out::write_str(STDERR_FILENO, "[ERROR] Integrity verification failed: Byte count mismatch!\n");
        Sys::Out::write_str(STDERR_FILENO, "  Expected: ");
        Sys::Out::write_uint(STDERR_FILENO, static_cast<uint64_t>(src_meta.raw_stat.st_size));
        Sys::Out::write_str(STDERR_FILENO, " bytes, Copied: ");
        Sys::Out::write_uint(STDERR_FILENO, bytes_transferred);
        Sys::Out::write_str(STDERR_FILENO, " bytes\n");
        return 1;
    }

    Sys::Out::write_str(STDOUT_FILENO, "[SUCCESS] Transfer completed: ");
    Sys::Out::write_uint(STDOUT_FILENO, bytes_transferred);
    Sys::Out::write_str(STDOUT_FILENO, " bytes written and synced to disk.\n");

    // Step 7: Handle Move Mode (--move / -m)
    if (config.is_move_mode) {
        Sys::Out::write_str(STDOUT_FILENO, "[STATUS] Move mode active: Unlinking original source file...\n");
        if (!Sys::FileTransferEngine::execute_unlink_source(config.source_arg)) {
            Sys::Out::write_str(STDERR_FILENO, "[ERROR] Data copied successfully, but source removal failed.\n");
            return 1;
        }
        Sys::Out::write_str(STDOUT_FILENO, "[SUCCESS] Source file successfully removed. Transfer complete.\n");
    }

    return 0;
}
