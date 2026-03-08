package main

import "base:intrinsics"
import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:crypto"
import "core:crypto/hmac"
import "core:crypto/hash"
import "core:thread"
import "core:sync"

import openssl "../openssl"

CHAT_PORT :: 9999
MAX_MESSAGE_SIZE :: 1024
HMAC_KEY_SIZE :: 32
HMAC_TAG_SIZE :: 32
MAX_PAYLOAD_SIZE :: MAX_MESSAGE_SIZE - HMAC_TAG_SIZE

INIT_MSG :: "INIT"
//ERROR_MSG :: "ERR_" //TODO: Error handling
REQ_KEY_MSG :: "KEY_"
RECV_MSG :: "MSG_"

Client_State :: enum {
	Error,
	Requesting_Pubkey,
	Ready,
}

recv_buf: [MAX_MESSAGE_SIZE]byte
socket: nbio.UDP_Socket
server_ep: nbio.Endpoint

hmac_key: [HMAC_KEY_SIZE]byte
state: Client_State = .Error

main_loop: ^nbio.Event_Loop

read_and_send_thread: ^thread.Thread

exiting: bool = false

hmac_mtx: sync.Mutex

init_connect :: proc(l: ^nbio.Event_Loop) {
	intrinsics.atomic_store_explicit(&state, .Requesting_Pubkey, .Release)
	init_buf: [4]byte
	copy(init_buf[:], INIT_MSG)
	nbio.send(socket, {init_buf[:]}, proc(op: ^nbio.Operation) {}, endpoint = server_ep, l = l)
}

main :: proc() {
	err := nbio.acquire_thread_event_loop()
	assert(err == nil)
	defer nbio.release_thread_event_loop()

	sock_err: nbio.Create_Socket_Error
	socket, sock_err = nbio.create_udp_socket(nbio.Address_Family.IP4)
	assert(sock_err == nil)

	net.set_option(socket, net.Socket_Option.Reuse_Address, true)
	bind_err := nbio.bind(socket, nbio.Endpoint{address = nbio.IP4_Any, port = 0})
	assert(bind_err == nil)

	resolve_err: net.Network_Error
	server_ep, resolve_err = net.resolve_ip4(fmt.tprintf("127.0.0.1:%d", CHAT_PORT))
	assert(resolve_err == nil)


	main_loop = nbio.current_thread_event_loop()

	// Phase 1: Send INIT to request server's public key
	init_connect(main_loop)
	nbio.recv(socket, {recv_buf[:]}, on_recv, l = main_loop)

	if err := nbio.run_until(&exiting); err != nil {
		fmt.eprintfln("run: %v", nbio.error_string(err))
		fmt.println("Exiting...")
		return
	}
	fmt.println("Exiting...")
}

on_recv :: proc(op: ^nbio.Operation) {
	defer if intrinsics.atomic_load_explicit(&state, .Acquire) != .Error {
		nbio.recv(socket, {recv_buf[:]}, on_recv, l = main_loop)
	}

	if op.recv.err != nil {
		fmt.eprintln("Recv error: ", op.recv.err)
		return
	}
	if op.recv.received == 0  {
		fmt.eprintln("Recv error zero length")
		return
	}

	data := op.recv.bufs[0][:op.recv.received]


	if string(data[:len(REQ_KEY_MSG)]) == REQ_KEY_MSG {
		fmt.println("Server requested key...")
		intrinsics.atomic_store_explicit(&state, .Requesting_Pubkey, .Release)
	}


	switch intrinsics.atomic_load_explicit(&state, .Acquire) {
	case .Error:
		intrinsics.atomic_store_explicit(&exiting, true, .Release)
		return
	case .Requesting_Pubkey:
		// Received server's public key (PEM)
		pem_str := string(data[len(REQ_KEY_MSG):])
		pubkey := openssl.RSA_load_public_pem(pem_str)
		if pubkey == nil {
			fmt.eprintln("Failed to load server public key")
			intrinsics.atomic_store_explicit(&exiting, true, .Release)
			intrinsics.atomic_store_explicit(&state, .Error, .Release)
			return
		}
		// Generate HMAC key and encrypt with server's public key
		sync.mutex_lock(&hmac_mtx)
		crypto.rand_bytes(hmac_key[:])
		encrypted: [256]byte
		n := openssl.RSA_encrypt(pubkey, hmac_key[:], encrypted[:])
		sync.mutex_unlock(&hmac_mtx)

		openssl.RSA_free(pubkey)
		if n < 0 {
			fmt.eprintln("RSA encrypt failed")
			intrinsics.atomic_store_explicit(&exiting, true, .Release)
			intrinsics.atomic_store_explicit(&state, .Error, .Release)
			return
		}
		out := make([]byte, n)
		copy(out, encrypted[:n])
		nbio.send_poly2(socket, {out}, out, context.allocator, on_send, endpoint = server_ep, all = true, l = main_loop)

		intrinsics.atomic_store_explicit(&state, .Ready, .Release)
		@static connected: bool = false
		//fmt.println("!ready!")
		if !connected {
			connected = true
			read_and_send_thread = thread.create_and_start(read_and_send)
		}
		return
	case .Ready:
		// Chat message with HMAC
		if op.recv.received < HMAC_TAG_SIZE + len(RECV_MSG) {
			fmt.eprintln("Invalid message length")
			return
		}
		if string(data[:len(RECV_MSG)]) != RECV_MSG {
			fmt.eprintln("Invalid message")
			return
		}
		payload_len := op.recv.received - HMAC_TAG_SIZE - len(RECV_MSG)
		payload := data[len(RECV_MSG):len(RECV_MSG) + payload_len]
		tag := data[len(RECV_MSG) + payload_len:]
		sync.mutex_lock(&hmac_mtx)
		if !hmac.verify(hash.Algorithm.SHA256, tag, payload, hmac_key[:]) {
			fmt.eprintln("HMAC verify failed")
			return
		}
		sync.mutex_unlock(&hmac_mtx)
		fmt.printf("received: %s\n", payload)
	}
}

on_send :: proc(op: ^nbio.Operation, m: []byte, allocator: mem.Allocator) {
	defer delete(m, allocator)
	if op.send.err != nil {
		fmt.eprintln("Send error:", op.send.err)
	}
}


read_and_send :: proc() {
	buf: [MAX_MESSAGE_SIZE]byte


	for {
		n: int
		for {
			n, _ = os.read(os.stdin, buf[:MAX_PAYLOAD_SIZE])
			if n > 0 do break
		}
		if intrinsics.atomic_load_explicit(&state, .Acquire) != .Ready {
			init_connect(main_loop)
			continue
		}
		if n > MAX_PAYLOAD_SIZE do n = MAX_PAYLOAD_SIZE
		if buf[n-1] == '\n' do n -= 1
		if n == 0 do continue

		out := make([]byte, n + HMAC_TAG_SIZE + len(RECV_MSG))
		copy(out, RECV_MSG)
		copy(out[len(RECV_MSG):], buf[:n])

		sync.mutex_lock(&hmac_mtx)
		hmac.sum(hash.Algorithm.SHA256, out[len(RECV_MSG) + n:], out[len(RECV_MSG):len(RECV_MSG) + n], hmac_key[:])
		sync.mutex_unlock(&hmac_mtx)

		nbio.send_poly2(socket, {out}, out, context.allocator, on_send, endpoint = server_ep, all = true, l = main_loop)
	}

	intrinsics.atomic_store_explicit(&exiting, true, .Release)
}
