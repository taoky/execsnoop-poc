# execsnoop-poc

A naive PoC of using aya to write kprobe eBPF tracing program in Rust.

Traced kprobes:

- `__x64_sys_execve`
- `__ia32_compat_sys_execve`
- `__x64_sys_execveat`
- `__ia32_compat_sys_execveat`
- `cgroup_procs_write` (catching changes in processes' cgroup)

Reference:

- https://github.com/willfindlay/suidsnoop
- https://github.com/Iceber/aya-tools/tree/main/execsnoop

## Portability

Aya does not fully support CO-RE, thus you may need to regenerate `vmlinux.rs` for your kernel version.

See:

- https://aya-rs.dev/book/aya/aya-tool/
- https://github.com/aya-rs/aya/issues/722

## Demo

1. 32-bit support (it is implemented by some dirty hacks though...)

    ```c
    #include <unistd.h>
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        if (execlp("vim", "vim", (char*) NULL) == -1) {
            perror("Failed to start vim");
            exit(EXIT_FAILURE);
        }
        return 0; // Unreachable, execlp replaces the process image if successful
    }
    // Compiled with: gcc -m32 example.c -o example
    ```

    ```console
    # fish shell
    > RUST_LOG=info cargo xtask run &| grep vim
    [2023-08-01T17:17:54Z INFO  execsnoop_poc] 115175 (parent 112230): /usr/bin/vim
    ```

2. execveat support

    ```c
    #define _GNU_SOURCE     
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdio.h>

    int main() {
        int dirfd;
        char *const argv[] = { "vim" };
        char *const envp[] = { NULL };

        int flags = AT_EMPTY_PATH;

        dirfd  = open("/usr/bin", O_DIRECTORY | O_CLOEXEC);
        if(dirfd == -1) {
            perror("open");
            return 1;
        }

        execveat(dirfd, "vim", argv, envp, flags);

        perror("execveat");  // Only reached if execveat() fails
        return 1;
    }
    ```

    ```console
    # fish shell
    > RUST_LOG=info cargo xtask run &| grep vim
    [2023-08-01T17:18:40Z INFO  execsnoop_poc] 115274 (parent 112230): vim
    ```

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
