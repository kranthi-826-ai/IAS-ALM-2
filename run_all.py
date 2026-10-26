import os
import sys
import subprocess
import time

BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))


def launch_aegis_suite():
    print("=" * 72)
    print("   AEGIS//OPS • Applied Cyber Defense & Cryptography Operations Suite")
    print("   Initiating Microservices (Projects 1, 2, 3) & Command UI...")
    print("=" * 72)

    active_processes = []

    # 1. Start Project 1 (AegisCrypt - Port 5101)
    p1_path = os.path.join(BASE_DIRECTORY, "Project1")
    print("\n[+] Initializing Project 1 (AegisCrypt) on http://localhost:5101 ...")
    env1 = os.environ.copy()
    env1["PORT"] = "5101"
    proc1 = subprocess.Popen([sys.executable, "app.py"], cwd=p1_path, env=env1)
    active_processes.append(("Project 1 (AegisCrypt)", proc1))

    # 2. Start Project 2 (NexusTunnel - Port 5102)
    p2_path = os.path.join(BASE_DIRECTORY, "Project2")
    print("[+] Initializing Project 2 (NexusTunnel) on http://localhost:5102 ...")
    env2 = os.environ.copy()
    env2["PORT"] = "5102"
    proc2 = subprocess.Popen([sys.executable, "app.py"], cwd=p2_path, env=env2)
    active_processes.append(("Project 2 (NexusTunnel)", proc2))

    # 3. Start Project 3 (Citadel Defense - Port 5103)
    p3_path = os.path.join(BASE_DIRECTORY, "Project3")
    print("[+] Initializing Project 3 (Citadel Defense) on http://localhost:5103 ...")
    env3 = os.environ.copy()
    env3["PORT"] = "5103"
    proc3 = subprocess.Popen([sys.executable, "app.py"], cwd=p3_path, env=env3)
    active_processes.append(("Project 3 (Citadel Defense)", proc3))

    # 4. Start Unified Dashboard UI (Port 3001)
    dash_path = os.path.join(BASE_DIRECTORY, "dashboard")
    print("[+] Initializing Unified Command Dashboard on http://localhost:3001 ...")
    npm_executable = "npm.cmd" if os.name == "nt" else "npm"
    proc_ui = subprocess.Popen([npm_executable, "run", "dev"], cwd=dash_path)
    active_processes.append(("Command Dashboard UI", proc_ui))

    time.sleep(3)
    print("\n" + "=" * 72)
    print("   ALL AEGIS//OPS SERVICES OPERATIONAL!")
    print("   -> Command Dashboard UI: http://localhost:3001")
    print("   -> AegisCrypt API:       http://localhost:5101")
    print("   -> NexusTunnel API:      http://localhost:5102")
    print("   -> Citadel Defense API:  http://localhost:5103")
    print("=" * 72)
    print("Press Ctrl+C to terminate all services.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Gracefully stopping all AegisOps services...")
        for label, proc in active_processes:
            print(f"    Terminating {label}...")
            proc.terminate()
            proc.wait()
        print("[✓] All services halted.")


if __name__ == "__main__":
    launch_aegis_suite()
