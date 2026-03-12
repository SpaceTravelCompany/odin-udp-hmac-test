# odin-udp-hmac-test

UDP-based chat client/server example. HMAC keys are exchanged securely via RSA; message integrity is verified with HMAC-SHA256.

## Run

1. Start the server first (default port **9999**):

   ```bash
   ./server
   ```

2. Start the client (connects to 127.0.0.1:9999):

   ```bash
   ./client
   ```

3. Type a line and press Enter in the client → message is sent to the server and echoed back to the same client.

## Protocol overview

1. **Connect**  
   Client sends `INIT` → server replies with `KEY_` + RSA public key (PEM).
2. **Key exchange**  
   Client generates a 32-byte HMAC key, encrypts it with the server’s public key, and sends `KEY_` + ciphertext. Server decrypts with its private key and registers that HMAC key for the client.
3. **Chat**  
   Subsequent messages use the format `MSG_` + payload + HMAC-SHA256 (32 bytes). Both server and client verify HMAC before processing.

Max message size 1024 bytes; max payload 1024 − 32 − 4 = 988 bytes.
