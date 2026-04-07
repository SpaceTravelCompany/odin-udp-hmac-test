package main

import "base:runtime"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:sync"
import "core:thread"

import openssl "shared:clibs/openssl"

CHAT_PORT :: 9999
MAX_MESSAGE_SIZE :: 1024
HMAC_KEY_SIZE :: 32
HMAC_TAG_SIZE :: 32
MAX_PAYLOAD_SIZE :: MAX_MESSAGE_SIZE - HMAC_TAG_SIZE

INIT_MSG :: "INIT"
//ERROR_MSG :: "ERR_" //TODO: Error handling
REQ_KEY_MSG :: "KEY_"
RECV_MSG :: "MSG_"

Client :: struct {
	end:      nbio.Endpoint,
	hmac_key: [HMAC_KEY_SIZE]byte,
}

Chat_Server :: struct {
	socket:      nbio.UDP_Socket,
	rsa_private: ^openssl.RSA,
	rsa_size:    int,
	pubkey_pem:  []byte,
	clients:     [dynamic]Client,
}

server: Chat_Server
recv_buf: [MAX_MESSAGE_SIZE]byte
thread_pool: thread.Pool

find_client :: proc(ep: nbio.Endpoint) -> ^Client {
	for &c in server.clients {
		if c.end == ep do return &c
	}
	return nil
}

add_client :: proc(ep: nbio.Endpoint, key: []byte) {
	new_client := Client {
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

	pubkey_pem := openssl.RSA_export_public_pem(rsa_private, context.allocator)
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
	defer delete(server.pubkey_pem)
	fmt.printf("UDP Chat Server on port %d (HMAC+RSA)\n", CHAT_PORT)

	thread.pool_init(&thread_pool, context.allocator, os.get_processor_core_count())
	thread.pool_start(&thread_pool)

	nbio.recv(socket, {recv_buf[:]}, on_recv, all = false)

	if err := nbio.run(); err != nil {
		fmt.eprintfln("run: %v", nbio.error_string(err))
	}
}

on_send :: proc(op: ^nbio.Operation, m: []byte, allocator: runtime.Allocator) {
	defer delete(m, allocator)
	if op.send.err != nil {
		fmt.eprintln("Send error:", op.send.err)
	}
}

WorkStruct :: struct {
	source: nbio.Endpoint,
	data:   []byte,
	sema:   sync.Sema,
	sock:   nbio.UDP_Socket,
	loop:   ^nbio.Event_Loop,
}

work :: proc(t: thread.Task) {
	work_struct := (^WorkStruct)(t.data)
	source := work_struct.source
	loop := work_struct.loop
	sock := work_struct.sock

	data, err := runtime.mem_alloc_non_zeroed(len(work_struct.data))
	if err != nil {
		fmt.eprintln("work allocate err : ", err)
		sync.sema_post(&work_struct.sema)
		return
	}
	mem.copy_non_overlapping(raw_data(data), raw_data(work_struct.data), len(work_struct.data))

	sync.sema_post(&work_struct.sema)
	defer delete(data)

	length := len(data)

	send_req_key :: proc(sock: nbio.UDP_Socket, ep: nbio.Endpoint, loop: ^nbio.Event_Loop) {
		out := make([]byte, len(server.pubkey_pem) + len(REQ_KEY_MSG))
		copy(out, REQ_KEY_MSG)
		copy(out[len(REQ_KEY_MSG):], server.pubkey_pem)
		nbio.send_poly2(
			sock,
			{out},
			out,
			context.allocator,
			on_send,
			endpoint = ep,
			all = true,
			l = loop,
		)
	}

	// Phase 1: INIT - send pre-exported public key
	if length >= len(INIT_MSG) && string(data[:len(INIT_MSG)]) == INIT_MSG {
		send_req_key(sock, source, loop)
		sync.sema_post(&work_struct.sema)
		return
	}
	if length < 4 + 1 {
		fmt.eprintln(
			"Client sent invalid message size:",
			length,
			" contents:",
			string(data),
			" -- expected at least 4 + 1 bytes",
		)
		return
	}

	// Phase 2: Encrypted HMAC key (RSA block size)
	client := find_client(source)
	if client == nil {
		decrypted: []byte = make([]byte, max(HMAC_KEY_SIZE, openssl.RSA_size(server.rsa_private)))
		defer delete(decrypted)
		n := openssl.RSA_decrypt(server.rsa_private, data[len(REQ_KEY_MSG):], decrypted[:])
		if n == HMAC_KEY_SIZE {
			add_client(source, decrypted[:HMAC_KEY_SIZE])
			fmt.printf("Client %v registered (HMAC key exchanged)\n", source)
		} else {
			fmt.eprintf("Client HMAC key exchange failed size : %d, d: %d\n", length, n)
			send_req_key(sock, source, loop)
		}
		return
	}

	// Phase 3: Chat message with HMAC
	if length < HMAC_TAG_SIZE + len(RECV_MSG) do return
	if string(data[:len(RECV_MSG)]) != RECV_MSG {
		fmt.eprintln("Invalid message size:", length, " contents:", string(data))
		send_req_key(sock, source, loop)
		return
	}

	payload_len := length - HMAC_TAG_SIZE - len(RECV_MSG)
	payload := data[len(RECV_MSG):len(RECV_MSG) + payload_len]
	tag := data[len(RECV_MSG) + payload_len:]

	if !hmac.verify(hash.Algorithm.SHA256, tag, payload, client.hmac_key[:]) {
		fmt.eprintln("HMAC verification failed, dropping message")
		send_req_key(sock, source, loop)
		return
	}
	fmt.printf("received %v: %s\n", client.end, payload)

	out := make([]byte, payload_len + HMAC_TAG_SIZE + len(RECV_MSG))
	copy(out, RECV_MSG)
	copy(out[len(RECV_MSG):], payload)
	hmac.sum(hash.Algorithm.SHA256, out[len(RECV_MSG) + payload_len:], payload, client.hmac_key[:])
	nbio.send_poly2(
		sock,
		{out},
		out,
		context.allocator,
		on_send,
		endpoint = client.end,
		all = true,
		l = loop,
	)
}


on_recv :: proc(op: ^nbio.Operation) {
	sock := op.recv.socket.(nbio.UDP_Socket)
	defer nbio.recv(sock, {recv_buf[:]}, on_recv, all = false)

	if op.recv.err != nil {
		fmt.eprintln("Recv error:", op.recv.err)
		return
	}
	if op.recv.received == 0 do return

	work_struct := WorkStruct {
		loop   = op.l,
		sock   = sock,
		source = op.recv.source,
		data   = op.recv.bufs[0][:op.recv.received],
	}
	thread.pool_add_task(&thread_pool, context.allocator, work, &work_struct)

	sync.sema_wait(&work_struct.sema)
}
