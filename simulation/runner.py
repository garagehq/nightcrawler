"""Simulation runner — drives the agent through mock scenarios."""

import subprocess
import sys
import os


def run_simulation(scenario: str = "basic_wpa2"):
    """Launch full dry-run simulation."""
    nc_home = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env["NC_DRY_RUN"] = "1"
    env["NC_HOME"] = nc_home
    env["NC_CONFIG"] = os.path.join(nc_home, "config.yaml")

    print(f"[SIM] Starting simulation: {scenario}")
    print(f"[SIM] NC_HOME: {nc_home}")
    print()

    # Start mock kali server
    mock_proc = subprocess.Popen(
        [sys.executable, "-m", "simulation.mock_kali_server", "5000"],
        cwd=nc_home,
        env=env,
    )

    try:
        # Run the agent
        agent_proc = subprocess.run(
            [sys.executable, "main.py"],
            cwd=nc_home,
            env=env,
        )
    except KeyboardInterrupt:
        print("\n[SIM] Interrupted.")
    finally:
        mock_proc.terminate()
        mock_proc.wait()
        print("[SIM] Simulation complete.")


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "basic_wpa2"
    run_simulation(scenario)
