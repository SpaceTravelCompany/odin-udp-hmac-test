package main

import "core:fmt"
import "core:nbio"
import "core:net"
import "core:mem"
import "core:crypto/hmac"
import "core:crypto/hash"

import openssl "shared:odin-http/openssl"

CHAT_PORT :: 9999
MAX_MESSAGE_SIZE :: 1024
HMAC_KEY_SIZE :: 32
HMAC_TAG_SIZE :: 32
MAX_PAYLOAD_SIZE :: MAX_MESSAGE_SIZE - HMAC_TAG_SIZE

INIT_MSG :: "INIT"

Client :: struct {
	end:      nbio.Endpoint,
	hmac_key: [HMAC_KEY_SIZE]byte,
}

Chat_Server :: struct {
	socket:       nbio.UDP_Socket,
	rsa_private:  ^openssl.RSA,
	rsa_size:     int,
	pubkey_pem:   []byte,
	clients:      [dynamic]Client,
}

server: Chat_Server
mtx_allocator: mem.Allocator
mtx_allocator_: mem.Mutex_Allocator
recv_buf: [MAX_MESSAGE_SIZE]byte

find_client :: proc(ep: nbio.Endpoint) -> ^Client {
	for &c in server.clients {
		if c.end == ep do return &c
	}
	return nil
}

add_client :: proc(ep: nbio.Endpoint, key: []byte) {
	new_client := Client{
		end = ep,
	}
	copy(new_client.hmac_key[:], key[:HMAC_KEY_SIZE])
	append(&server.clients, new_client)
}

main :: proc() {
	err := nbio.acquire_thread_event_loop()
	if err != nil {
		fmt.eprintf("failed to acquire thread event loop: %d\n", err)
		return
	}
	defer nbio.release_thread_event_loop()

	socket, sock_err := nbio.create_udp_socket(nbio.Address_Family.IP4)
	assert(sock_err == nil)

	mem.mutex_allocator_init(&mtx_allocator_, context.allocator)
	mtx_allocator = mem.mutex_allocator(&mtx_allocator_)

	net.set_option(socket, net.Socket_Option.Reuse_Address, true)
	bind_err := nbio.bind(socket, nbio.Endpoint{address = nbio.IP4_Any, port = CHAT_PORT})
	assert(bind_err == nil)

	// Generate RSA key pair at startup (no file needed)
	// Alternative: load from file - RSA_load_private_pem_file("server-private.pem"), RSA_load_public_pem_file("server-public.pem")
	rsa_private := openssl.RSA_generate_key(2048)
	if rsa_private == nil {
		fmt.eprintln("ERROR: failed to generate RSA key")
		return
	}
	defer openssl.RSA_free(rsa_private)

	pubkey_pem := openssl.RSA_export_public_pem(rsa_private, mtx_allocator)
	if pubkey_pem == nil {
		fmt.eprintln("ERROR: failed to export public key PEM")
		openssl.ERR_print_errors_stderr()
		return
	}
	server = Chat_Server {
		socket      = socket,
		rsa_private = rsa_private,
		rsa_size    = int(openssl.RSA_size(rsa_private)),
		pubkey_pem  = pubkey_pem,
	}
	defer delete(server.pubkey_pem, mtx_allocator)
	fmt.printf("UDP Chat Server on port %d (HMAC+RSA)\n", CHAT_PORT)

	nbio.recv(socket, {recv_buf[:]}, on_recv, all = false)

	if err := nbio.run(); err != nil {
		fmt.eprintfln("run: %v", nbio.error_string(err))
	}
}

on_recv :: proc(op: ^nbio.Operation) {
	sock := op.recv.socket.(nbio.UDP_Socket)
	defer nbio.recv(sock, {recv_buf[:]}, on_recv, all = false)

	if op.recv.err != nil {
		fmt.eprintln("Recv error:", op.recv.err)
		return
	}
	if op.recv.received == 0 do return

	source := op.recv.source
	data := op.recv.bufs[0][:op.recv.received]

	// Phase 1: INIT - send pre-exported public key
	if op.recv.received >= 4 && string(data[:4]) == INIT_MSG {
		out := make([]byte, len(server.pubkey_pem), mtx_allocator)
		copy(out, server.pubkey_pem)
		nbio.send_poly(sock, {out}, out, proc(op: ^nbio.Operation, m: []byte) {
			defer delete(m, mtx_allocator)
		}, endpoint = source, all = true)
		return
	}

	// Phase 2: Encrypted HMAC key (RSA block size)
	client := find_client(source)
	if client == nil {
		decrypted: []byte = make([]byte, max(HMAC_KEY_SIZE, openssl.RSA_size(server.rsa_private)),
		 mtx_allocator)
		defer delete(decrypted, mtx_allocator)
		n := openssl.RSA_decrypt(server.rsa_private, data, decrypted[:])
		if n == HMAC_KEY_SIZE {
			add_client(source, decrypted[:HMAC_KEY_SIZE])
			fmt.printf("Client %v registered (HMAC key exchanged)\n", source)
		} else {
			fmt.printf("Client HMAC key exchange failed size : %d, d: %d\n", 
			op.recv.received, n)
		}
		return
	}

	// Phase 3: Chat message with HMAC
	if client == nil do return
	if op.recv.received < HMAC_TAG_SIZE do return

	payload_len := op.recv.received - HMAC_TAG_SIZE
	payload := data[:payload_len]
	tag := data[payload_len:payload_len + HMAC_TAG_SIZE]

	if !hmac.verify(hash.Algorithm.SHA256, tag, payload, client.hmac_key[:]) {
		fmt.eprintln("HMAC verification failed, dropping message")
		return
	}

	out := make([]byte, payload_len + HMAC_TAG_SIZE, mtx_allocator)
	copy(out, payload)
	hmac.sum(hash.Algorithm.SHA256, out[payload_len:], payload, client.hmac_key[:])
	nbio.send_poly(sock, {out}, out, proc(op: ^nbio.Operation, m: []byte) {
		defer delete(m, mtx_allocator)
	}, endpoint = client.end, all = true)
}
