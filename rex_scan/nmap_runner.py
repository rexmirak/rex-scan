"""Run nmap and handle output."""
import subprocess
import shlex
from pathlib import Path


def run_nmap(*, target: str, ports: str = "", timing: str = "T3", output_xml: str, verbose: bool = False, sudo_password: str = "", nmap_flags: str = ""):
    """
    Run an nmap scan and write XML output to output_xml.

    - If `nmap_flags` provided, it completely overrides default flags (custom mode).
    - Otherwise, if `ports` is empty, use --top-ports 1000 for a reasonable default.
    - Default runs service detection (-sV).
    - If sudo_password provided, use -sS (SYN scan) with sudo, otherwise -sT (connect scan).
    """
    output_path = Path(output_xml)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if nmap_flags:
        # Custom mode: user provides complete nmap flags
        # Parse flags and combine with required output flag
        custom_args = shlex.split(nmap_flags)
        cmd = ["nmap", "-oX", str(output_path)] + custom_args + [target]
    else:
        # Standard mode: build command from parameters
        # Choose scan type based on sudo availability
        scan_type = "-sS" if sudo_password else "-sT"
        
        cmd = ["nmap", "-oX", str(output_path), scan_type, "-sV", f"-T{timing[-1] if timing.startswith('T') else timing}"]
        if ports:
            # allow passing comma-separated or range
            cmd += ["-p", ports]
        else:
            cmd += ["--top-ports", "1000"]
        cmd.append(target)

    # If sudo password provided, prepend sudo -S
    if sudo_password:
        cmd = ["sudo", "-S"] + cmd
    
    # Run subprocess. If verbose, stream stdout/stderr to console so the user sees progress.
    if verbose:
        print("[nmap] command:", " ".join(cmd if not sudo_password else ["sudo"] + cmd[2:]), flush=True)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if sudo_password else None,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        # Send password if using sudo
        if sudo_password:
            proc.stdin.write(sudo_password + '\n')
            proc.stdin.flush()
            proc.stdin.close()
        
        # stream with explicit flushing
        try:
            for line in proc.stdout:
                print(line, end="", flush=True)
        except KeyboardInterrupt:
            proc.kill()
            raise
        ret = proc.wait()
        if ret != 0:
            raise RuntimeError(f"nmap failed (rc={ret})")
    else:
        if sudo_password:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(input=sudo_password + '\n')
            if proc.returncode != 0:
                raise RuntimeError(f"nmap failed: {stderr.strip()}")
        else:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")

    return str(output_path)
