package main

import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:crypto"
import "core:crypto/hmac"
import "core:crypto/hash"

import openssl "./openssl"

CHAT_PORT :: 9999
MAX_MESSAGE_SIZE :: 1024
HMAC_KEY_SIZE :: 32
HMAC_TAG_SIZE :: 32
MAX_PAYLOAD_SIZE :: MAX_MESSAGE_SIZE - HMAC_TAG_SIZE

INIT_MSG :: "INIT"

Client_State :: enum {
	Init,
	Requesting_Pubkey,
	Sending_Key,
	Ready,
}

recv_buf: [MAX_MESSAGE_SIZE]byte
socket: nbio.UDP_Socket
server_ep: nbio.Endpoint

hmac_key: [HMAC_KEY_SIZE]byte
state: Client_State = .Init
mtx_allocator: mem.Allocator
mtx_allocator_: mem.Mutex_Allocator

main :: proc() {
	err := nbio.acquire_thread_event_loop()
	assert(err == nil)
	defer nbio.release_thread_event_loop()

	mem.mutex_allocator_init(&mtx_allocator_, context.allocator)
	mtx_allocator = mem.mutex_allocator(&mtx_allocator_)

	sock_err: nbio.Create_Socket_Error
	socket, sock_err = nbio.create_udp_socket(nbio.Address_Family.IP4)
	assert(sock_err == nil)

	net.set_option(socket, net.Socket_Option.Reuse_Address, true)
	bind_err := nbio.bind(socket, nbio.Endpoint{address = nbio.IP4_Any, port = 0})
	assert(bind_err == nil)

	resolve_err: net.Network_Error
	server_ep, resolve_err = net.resolve_ip4(fmt.tprintf("127.0.0.1:%d", CHAT_PORT))
	assert(resolve_err == nil)

	// Phase 1: Send INIT to request server's public key
	state = .Requesting_Pubkey
	init_buf: [4]byte
	copy(init_buf[:], INIT_MSG)
	nbio.send(socket, {init_buf[:]}, proc(op: ^nbio.Operation) {}, endpoint = server_ep)
	nbio.recv(socket, {recv_buf[:]}, on_recv)
	nbio.run()
}

on_recv :: proc(op: ^nbio.Operation) {
	if op.recv.err != nil do return
	if op.recv.received == 0 do return

	data := op.recv.bufs[0][:op.recv.received]

	switch state {
	case .Init:
		return
	case .Requesting_Pubkey:
		// Received server's public key (PEM)
		pem_str := string(data)
		pubkey := openssl.RSA_load_public_pem(pem_str)
		if pubkey == nil {
			fmt.eprintln("Failed to load server public key")
			return
		}
		// Generate HMAC key and encrypt with server's public key
		crypto.rand_bytes(hmac_key[:])
		encrypted: [256]byte
		n := openssl.RSA_encrypt(pubkey, hmac_key[:], encrypted[:])
		openssl.RSA_free(pubkey)
		if n < 0 {
			fmt.eprintln("RSA encrypt failed")
			return
		}
		out := make([]byte, n, mtx_allocator)
		copy(out, encrypted[:n])
		nbio.send_poly(socket, {out}, out, proc(op: ^nbio.Operation, m: []byte) {
			defer delete(m, mtx_allocator)
			
		}, endpoint = server_ep, all = true)

		state = .Ready
		read_and_send()
	case .Sending_Key:
		// Unexpected (server doesn't ack key)
		return
	case .Ready:
		// Chat message with HMAC
		if op.recv.received < HMAC_TAG_SIZE do return
		payload_len := op.recv.received - HMAC_TAG_SIZE
		payload := data[:payload_len]
		tag := data[payload_len:payload_len + HMAC_TAG_SIZE]
		if !hmac.verify(hash.Algorithm.SHA256, tag, payload, hmac_key[:]) {
			fmt.eprintln("HMAC verify failed")
			nbio.recv(socket, {recv_buf[:]}, on_recv)
			return
		}
		fmt.printf("%s\n", payload)
		read_and_send()
	}
}

on_send :: proc(op: ^nbio.Operation, m: []byte) {
	defer delete(m, mtx_allocator)
}

read_and_send :: proc() {
	n: int
	for {
		n, _ = os.read(os.stdin, recv_buf[:MAX_PAYLOAD_SIZE])
		if n > 0 do break
	}
	if n > MAX_PAYLOAD_SIZE do n = MAX_PAYLOAD_SIZE

	out := make([]byte, n + HMAC_TAG_SIZE, mtx_allocator)
	copy(out, recv_buf[:n])
	hmac.sum(hash.Algorithm.SHA256, out[n:], out[:n], hmac_key[:])
	nbio.send_poly(socket, {out}, out, on_send, endpoint = server_ep, all = true)
	nbio.recv(socket, {recv_buf[:]}, on_recv)
}
