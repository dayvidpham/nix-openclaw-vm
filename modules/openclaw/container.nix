# OpenClaw Container Image Definition
# Builds a security-hardened container image for OpenClaw instances
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;

  inherit (lib)
    mkOption
    types
    ;

  # Base container image with OpenClaw and minimal dependencies
  # Using Podman's native container build instead of nix2container for simplicity
  openclawContainerImage = pkgs.dockerTools.buildLayeredImage {
    name = "openclaw";
    tag = "latest";

    contents = with pkgs; [
      # Runtime dependencies
      nodejs_22
      coreutils
      bashInteractive  # Required for healthchecks, but limited shell access
      cacert           # TLS certificates for API calls
      curl             # For health endpoint checking

      # OpenClaw gateway from nix-openclaw flake
      cfg.container.gatewayPackage
    ];

    # Security hardening configuration
    config = {
      # Use stable symlink path instead of Nix store path
      # The symlink is created in extraCommands below
      Cmd = [ "/usr/local/bin/openclaw" ];
      WorkingDir = "/app";
      User = "openclaw:openclaw";

      # Environment defaults (overridable at runtime)
      Env = [
        "NODE_ENV=production"
        "HOME=/home/openclaw"
      ];

      # Healthcheck configuration
      Healthcheck = {
        Test = [ "CMD" "curl" "-sf" "http://localhost:18789/health" ];
        Interval = 30000000000;  # 30s in nanoseconds
        Timeout = 5000000000;    # 5s in nanoseconds
        Retries = 3;
      };

      # Labels for container metadata
      Labels = {
        "org.opencontainers.image.title" = "OpenClaw";
        "org.opencontainers.image.description" = "Secure OpenClaw AI Assistant Container";
        "org.opencontainers.image.vendor" = "Custom NixOS Build";
      };
    };

    # Create non-root user and required directories
    extraCommands = ''
      # Create openclaw user (UID 1000 inside container)
      mkdir -p etc
      echo 'root:x:0:0:root:/root:/bin/sh' > etc/passwd
      echo 'openclaw:x:1000:1000:OpenClaw User:/home/openclaw:/bin/sh' >> etc/passwd

      echo 'root:x:0:' > etc/group
      echo 'openclaw:x:1000:' >> etc/group

      # Create home and app directories
      mkdir -p home/openclaw
      mkdir -p home/openclaw/.config
      mkdir -p app
      mkdir -p run/secrets

      # Create stable symlink to openclaw binary
      # This avoids Nix store path changes breaking the container Cmd
      mkdir -p usr/local/bin
      ln -sf ${cfg.container.gatewayPackage}/bin/openclaw usr/local/bin/openclaw

      # Set ownership (will be applied at runtime)
      # Note: dockerTools doesn't support chown in extraCommands,
      # so we rely on the container runtime to handle this
    '';

    # Maximum layers for efficient caching
    maxLayers = 120;
  };

  # Seccomp profile for container hardening
  # Based on Docker's default profile with additional restrictions
  seccompProfile = pkgs.writeText "openclaw-seccomp.json" (builtins.toJSON {
    defaultAction = "SCMP_ACT_ERRNO";
    defaultErrnoRet = 1;  # EPERM
    archMap = [
      {
        architecture = "SCMP_ARCH_X86_64";
        subArchitectures = [ "SCMP_ARCH_X86" "SCMP_ARCH_X32" ];
      }
    ];
    syscalls = [
      # Allow common syscalls needed for Node.js
      {
        names = [
          "accept" "accept4" "access" "arch_prctl" "bind" "brk"
          "capget" "capset" "chdir" "chmod" "chown" "clock_getres"
          "clock_gettime" "clock_nanosleep" "close" "connect"
          "dup" "dup2" "dup3" "epoll_create" "epoll_create1"
          "epoll_ctl" "epoll_pwait" "epoll_wait" "eventfd" "eventfd2"
          "execve" "exit" "exit_group" "faccessat" "faccessat2"
          "fadvise64" "fallocate" "fchdir" "fchmod" "fchmodat"
          "fchown" "fchownat" "fcntl" "fdatasync" "fgetxattr"
          "flistxattr" "flock" "fork" "fstat" "fstatfs" "fsync"
          "ftruncate" "futex" "getcwd" "getdents" "getdents64"
          "getegid" "geteuid" "getgid" "getgroups" "getpeername"
          "getpgid" "getpgrp" "getpid" "getppid" "getpriority"
          "getrandom" "getresgid" "getresuid" "getrlimit" "getrusage"
          "getsid" "getsockname" "getsockopt" "gettid" "gettimeofday"
          "getuid" "getxattr" "inotify_add_watch" "inotify_init"
          "inotify_init1" "inotify_rm_watch" "ioctl" "kill" "lchown"
          "lgetxattr" "link" "linkat" "listen" "listxattr" "llistxattr"
          "lseek" "lstat" "madvise" "membarrier" "memfd_create"
          "mincore" "mkdir" "mkdirat" "mknod" "mknodat" "mlock"
          "mlock2" "mlockall" "mmap" "mprotect" "mremap" "msgctl"
          "msgget" "msgrcv" "msgsnd" "msync" "munlock" "munlockall"
          "munmap" "nanosleep" "newfstatat" "open" "openat" "pause"
          "pipe" "pipe2" "poll" "ppoll" "prctl" "pread64" "preadv"
          "preadv2" "prlimit64" "pselect6" "pwrite64" "pwritev"
          "pwritev2" "read" "readahead" "readlink" "readlinkat"
          "readv" "recvfrom" "recvmmsg" "recvmsg" "remap_file_pages"
          "rename" "renameat" "renameat2" "restart_syscall" "rmdir"
          "rt_sigaction" "rt_sigpending" "rt_sigprocmask" "rt_sigqueueinfo"
          "rt_sigreturn" "rt_sigsuspend" "rt_sigtimedwait" "rt_tgsigqueueinfo"
          "sched_getaffinity" "sched_getattr" "sched_getparam"
          "sched_get_priority_max" "sched_get_priority_min" "sched_getscheduler"
          "sched_rr_get_interval" "sched_setaffinity" "sched_setattr"
          "sched_setparam" "sched_setscheduler" "sched_yield" "seccomp"
          "select" "semctl" "semget" "semop" "semtimedop" "sendfile"
          "sendmmsg" "sendmsg" "sendto" "setfsgid" "setfsuid" "setgid"
          "setgroups" "setitimer" "setpgid" "setpriority"
          "setregid" "setresgid" "setresuid" "setreuid" "setrlimit"
          "setsid" "setsockopt" "set_tid_address" "setuid" "setxattr"
          "shmat" "shmctl" "shmdt" "shmget" "shutdown" "sigaltstack"
          "signalfd" "signalfd4" "socket" "socketpair" "splice" "stat"
          "statfs" "statx" "symlink" "symlinkat" "sync" "sync_file_range"
          "syncfs" "sysinfo" "tee" "tgkill" "time" "timer_create"
          "timer_delete" "timerfd_create" "timerfd_gettime" "timerfd_settime"
          "timer_getoverrun" "timer_gettime" "timer_settime" "times"
          "tkill" "truncate" "umask" "uname" "unlink" "unlinkat"
          "unshare" "utime" "utimensat" "utimes" "vfork" "vmsplice"
          "wait4" "waitid" "write" "writev"
        ];
        action = "SCMP_ACT_ALLOW";
      }
      # Allow clone with specific flags for threading
      {
        names = [ "clone" ];
        action = "SCMP_ACT_ALLOW";
        args = [
          { index = 0; value = 2114060288; valueTwo = 0; op = "SCMP_CMP_MASKED_EQ"; }
        ];
      }
    ];
  });

in
{
  options.CUSTOM.virtualisation.openclaw.container = {
    gatewayPackage = mkOption {
      type = types.nullOr types.package;
      default = null;
      description = "OpenClaw gateway package from nix-openclaw flake";
    };

    image = mkOption {
      type = types.package;
      default = openclawContainerImage;
      description = "The OpenClaw container image package";
    };

    seccompProfile = mkOption {
      type = types.path;
      default = seccompProfile;
      description = "Path to the seccomp profile JSON for container hardening";
    };

    registry = mkOption {
      type = types.str;
      default = "";
      description = "Optional container registry to pull from instead of local build";
      example = "ghcr.io/openclaw/openclaw:latest";
    };
  };
}
