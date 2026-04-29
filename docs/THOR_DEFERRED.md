# Features Deferred to Thor (AGX 128GB)

These features are too heavy for the OnePlus 8 (12GB RAM, 2B model)
and are deferred to Thor for implementation.

## 6. Full NVD/Vulners Offline Mirror
- NVD JSON feeds: ~2GB compressed, requires parsing + indexing
- MongoDB or PostgreSQL backend for fast CVE queries
- Thor can run `cve-search` (Python + MongoDB) and serve API queries
  to the phone agent over Tailscale
- Phone agent would call `curl http://thor:9999/cve/openssh/8.2p1`
  to get version-specific CVEs with exploit references
- **Why not phone**: MongoDB + full NVD data = 4-8GB RAM, 10GB+ disk
  index. Phone can't spare the RAM alongside llama-server.

## 7. Thinking/Reasoning Mode for Exploit Planning
- Qwen3.5-2B with thinking enabled burns 3000+ tokens on simple
  decisions — with 8192 context and 6000 budget, this leaves almost
  nothing for the actual command
- Thor with a 70B model (Qwen-70B, Llama-70B) could do multi-step
  reasoning: "Found Samba 4.17 → check CVE-2023-3961 → path traversal
  via pipe name → craft smbclient command"
- **Phone workaround**: Hardcoded exploit chains in prompts (implemented)
  achieve 80% of the same result without reasoning overhead

## 8. Complex Metasploit Integration
- The 2B model can't reliably construct multi-line msfconsole syntax:
  `msfconsole -q -x "use exploit/...; set RHOSTS ...; set PAYLOAD ...; run; exit"`
- Metasploit itself uses ~200MB+ RAM, which is tight alongside
  llama-server (3.2GB) + agent + tools
- Thor could run metasploit as a persistent service and receive
  "run module X against host Y" commands from the phone agent
- **Phone workaround**: nmap NSE vuln scripts + nxc cover most of the
  same ground without metasploit's memory overhead

## Architecture When Thor Is Online
```
Phone Agent → finds version/CVE → asks Thor for exploit plan
Thor (70B model + NVD DB + Metasploit) → returns specific exploit command
Phone Agent → executes the command via kali-mcp
```

The phone agent handles: scanning, enumeration, credential testing,
simple exploitation (NSE scripts, nxc, searchsploit, impacket).

Thor handles: CVE research, complex exploit planning, metasploit
modules, multi-step reasoning chains, payload generation.
