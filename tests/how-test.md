How to run test scenarios

Overview
- Each folder under `tests/` is a self-contained scenario (e.g. `tests/test-fiskal-pro`).
- New scenarios will be added over time, each with its own `compose.yml` and `how-test.md`.

Steps
1. Open the scenario folder you want to run (example: `tests/test-fiskal-pro`).
2. From the repository root, start the stack:
   `docker compose -f tests/test-fiskal-pro/compose.yml up -d`
3. Open the UI in your browser:
   http://localhost:9075/
4. Set `deviceIp` (host or IP) and `devicePort` to your LAN device.
5. Submit the form and verify the response.
6. Stop the stack when done:
   `docker compose -f tests/test-fiskal-pro/compose.yml down`
