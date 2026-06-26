# nmap_to_excel

Convert an nmap XML scan into a multi-sheet Excel workbook that surfaces hosts,
services, and notable findings (CVEs/vulnerabilities and discovered
directories/endpoints) at a glance.

## Requirements

- Python 3
- [`openpyxl`](https://pypi.org/project/openpyxl/)

```bash
pip3 install openpyxl
```

## Usage

Run these nmap commands:
###Masscan
sudo masscan -iL INPUT_FILE.txt -p 0-65535 -oG MASSCAN_OUTPUT --max-rate=4000    
(Note, 4000 = ~4 MB/sec.  This number can be scaled up or down based on size of network and performance, however, do not exceede 8000.  Generally it's best to start with 1000 or 2000, look at the estiamted duration, then scale up if necessary.
Ports: cat MASSCAN_OUTPUT.gnmap |grep Host |cut -d '/' -f 1 | cut -d ' ' -f 5 | sort -u  | tr '\n' ','
Hosts: cat MASSCAN_OUTPUT.gnmap |grep Host |cut -d ' ' -f 3 | sort -u

###Nmap
~~TCP ONLY~~
sudo nmap -v -sS -sV -sC -T4 -Pn -R -O --version-all --reason --script default,http-enum,http-default-accounts,http-config-backup,http-auth-finder,http-method-tamper,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2012-1823,smb-enum-users,smb-enum-shares,nfs-showmount,nfs-statfs,dns-zone-transfer,dns-update,sip-enum-users,afp-ls,ntp-monlist,http-vmware-path-vuln,http-vuln-cve2013-0156,http-coldfusion-subzero,http-adobe-coldfusion-apsa1301,ssl-heartbleed -iL INPUT_FILE.txt -oA OUTPUT_FILE_OUT -p REFERENCE_MASSCAN_PORTS
~~UDP ONLY~~
sudo nmap -v -sU -sV -sC -T4 -Pn -R --reason --script default,smb-enum-users,smb-enum-shares,nfs-showmount,nfs-statfs,dns-zone-transfer,dns-update,sip-enum-users,ntp-monlist,tftp-enum -iL INPUT_FILE.txt -oA OUTPUT_FILE_OUT -p 53,67-69,123,135,137-139,161,445,500,520,623,631,1434,1900,5060-5061,11211
~~ALL~~
sudo nmap -v -sS -sU -sV -sC -T4 -Pn -R -O --version-all --reason --script default,http-enum,http-default-accounts,http-config-backup,http-auth-finder,http-method-tamper,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2012-1823,smb-enum-users,smb-enum-shares,nfs-showmount,nfs-statfs,dns-zone-transfer,dns-update,sip-enum-users,afp-ls,ntp-monlist,http-vmware-path-vuln,http-vuln-cve2013-0156,http-coldfusion-subzero,http-adobe-coldfusion-apsa1301,ssl-heartbleed,nfs-showmount,nfs-statfs,dns-zone-transfer,dns-update,sip-enum-users,ntp-monlist,tftp-enum -p T:1-65535,U:53,67-69,123,135,137-139,161,445,500,520,623,631,1434,1900,5060-5061 -iL INPUT_FILE -oA OUTPUT_FILE

```bash
python3 nmap_to_excel.py [INPUT.xml] [OUTPUT.xlsx]
```

- `INPUT.xml`  — nmap XML output (default: `OUTPUT_FILE_OUT.xml`)
- `OUTPUT.xlsx` — workbook to write (default: `OUTPUT_FILE_OUT.xlsx`)

Generate the input with nmap's `-oX` (or `-oA`) flag:

```bash
nmap -sV -sC -oX OUTPUT_FILE_OUT.xml <targets>
```

### Examples

```bash
# Use the defaults
python3 nmap_to_excel.py

# Explicit input/output
python3 nmap_to_excel.py OUTPUT_FILE_OUT.xml OUTPUT_FILE_OUT.xlsx

# Run against a different scan (e.g. the UDP scan)
python3 nmap_to_excel.py udp_out.xml udp_out.xlsx
```

On success it prints a summary, e.g.:

```
Wrote OUTPUT_FILE_OUT.xlsx
  Hosts:    806
  Services: 7489
  Findings: 865 (69 CVE/vuln, 796 dir/endpoint)
```

## Output workbook

Every sheet has a frozen header row, an auto-filter, and auto-sized columns.

### Hosts

One row per host that was up — the at-a-glance summary view.

| Column | Description |
| --- | --- |
| IP | IPv4/IPv6 address |
| Hostname | First resolved hostname (if any) |
| MAC | MAC address (if seen) |
| OS | Best OS match (if detected) |
| Open Ports | Count of open ports |
| CVE Count | Number of distinct CVEs/vulns noted on the host |
| Dir/Endpoint Count | Number of directory/endpoint findings |
| CVEs | Comma-separated list of the CVE IDs found |

### Services

One row per scanned port.

| Column | Description |
| --- | --- |
| IP / Hostname | Host the port belongs to |
| Port / Protocol / State | e.g. `443` / `tcp` / `open` |
| Service / Product / Version / Extra Info | Service-detection details |

### Findings

One row per notable NSE script result, color-coded by category.

| Column | Description |
| --- | --- |
| IP / Hostname / Port | Where the finding was observed |
| Category | `CVE / Vulnerability` (🟧) or `Directory / Endpoint` (🟩) |
| Script | NSE script ID that produced the result |
| CVEs | Any `CVE-####-####` IDs parsed from the output |
| Details | Raw script output |

## How findings are classified

Each NSE script result is bucketed by `nmap_to_excel.py`:

- **CVE / Vulnerability** — the script ID contains `vuln` or `cve`, **or** the
  output contains a `CVE-YYYY-NNNN` identifier (matched by regex). Parsed CVE
  IDs are deduplicated and rolled up onto the host row.
- **Directory / Endpoint** — path/content-discovery scripts:
  `http-enum`, `http-robots.txt`, `http-config-backup`,
  `http-default-accounts`, `http-vhosts`, `http-backup-finder`.
- Anything else is ignored in the Findings sheet (services still appear on the
  Services sheet).

To add or change categories, edit the `DIR_SCRIPTS` set and the `classify()`
function in `nmap_to_excel.py`.

## Notes

- The script reads the nmap **XML** output (`.xml`), not the plain-text
  `.nmap` report — the XML is structured and parses reliably.
- Hosts marked `down` are skipped.
- Parsing uses streaming (`iterparse`), so large scans are handled without
  loading the whole file into memory.
