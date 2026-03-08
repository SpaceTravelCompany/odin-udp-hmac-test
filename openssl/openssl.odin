package openssl

import "core:c"
import "core:c/libc"
import "core:strings"
import "core:time"

//SHARED :: #config(OPENSSL_SHARED, false) //edited

when ODIN_ARCH == .amd64 {
    __ARCH_end :: "_amd64"
} else when ODIN_ARCH == .i386 {
    __ARCH_end :: "_i386"
} else when ODIN_ARCH == .arm64 {
    __ARCH_end :: "_arm64"
} else when ODIN_ARCH == .riscv64 {
    __ARCH_end :: "_riscv64"
} else when ODIN_ARCH == .arm32 {
    __ARCH_end :: "_arm32"
} else when ODIN_OS == .JS || ODIN_OS == .WASI {
    __ARCH_end :: "_wasm"
}

when ODIN_OS == .Windows && ODIN_PLATFORM_SUBTARGET == .Default {
	ARCH_end :: __ARCH_end + ".lib"
	ARCH_end_so :: __ARCH_end + ".dll"
} else {
	ARCH_end :: __ARCH_end + ".a"
	ARCH_end_so :: __ARCH_end + ".so"
}

when ODIN_PLATFORM_SUBTARGET == .Android {
	foreign import lib {
		"lib/android/libssl" + ARCH_end,
		"lib/android/libcrypto" + ARCH_end,
	}
} else when ODIN_OS == .Windows {
	foreign import lib {
		"lib/windows/libssl" + ARCH_end,
		"lib/windows/libcrypto" + ARCH_end,
		"system:ws2_32.lib",
		"system:gdi32.lib",
		"system:advapi32.lib",
		"system:crypt32.lib",
		"system:user32.lib",
	}
} else when ODIN_OS == .Darwin {
	foreign import lib {
		"system:ssl.3",
		"system:crypto.3",
	}
} else {
	// foreign import lib {
	// 	"system:ssl",
	// 	"system:crypto",
	// }
	foreign import lib {
		"lib/linux/libssl" + ARCH_end,
		"lib/linux/libcrypto" + ARCH_end,
	}
}

Version :: bit_field u32 {
	pre_release: uint | 4,
	patch:       uint | 16,
	minor:       uint | 8,
	major:       uint | 4,
}

VERSION: Version

@(private, init)
version_check :: proc "contextless" () {
	VERSION = Version(OpenSSL_version_num())
	assert_contextless(VERSION.major == 3, "invalid OpenSSL library version, expected 3.x")
}

SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}
BIO :: struct {}
BIO_ADDR :: struct {} // opaque - DTLSv1_listen accepts rawptr to sockaddr_storage
RSA :: struct {}
BIGNUM :: struct {}

// RSA padding
RSA_PKCS1_PADDING     :: 1
RSA_NO_PADDING        :: 3
RSA_PKCS1_OAEP_PADDING :: 4

// DTLS/UDP usage (see dtls_udp_echo.c):
// Server: socket(UDP) -> bind -> loop: BIO_new_dgram(fd,BIO_NOCLOSE), SSL_new, SSL_set_bio,
//   SSL_set_options(SSL_OP_COOKIE_EXCHANGE), DTLSv1_listen(ssl, &client_addr), spawn handler
// Client: socket(UDP) -> connect -> BIO_new_dgram(fd,BIO_CLOSE), BIO_ctrl_set_connected,
//   SSL_set_bio, SSL_connect
// Timeout: struct timeval -> BIO_ctrl_set_recv_timeout; check BIO_dgram_recv_timedout on WANT_READ

// BIO close flags
BIO_NOCLOSE :: 0x00
BIO_CLOSE   :: 0x01

// BIO ctrl commands for DTLS/UDP
BIO_C_SET_FD                :: 104
BIO_CTRL_DGRAM_CONNECT      :: 31
BIO_CTRL_DGRAM_SET_CONNECTED :: 32
BIO_CTRL_DGRAM_SET_RECV_TIMEOUT :: 33
BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP :: 37
BIO_CTRL_DGRAM_GET_PEER     :: 46
BIO_CTRL_RESET              :: 1
BIO_CTRL_PENDING            :: 10  /* is there more data buffered */

// SSL options
SSL_OP_COOKIE_EXCHANGE :: 1 << 13

// SSL shutdown flags
SSL_RECEIVED_SHUTDOWN :: 2

// SSL error codes
SSL_ERROR_NONE    :: 0
SSL_ERROR_SSL     :: 1
SSL_ERROR_WANT_READ  :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_WANT_X509_LOOKUP :: 4
SSL_ERROR_SYSCALL  :: 5
SSL_ERROR_ZERO_RETURN :: 6
SSL_ERROR_WANT_CONNECT :: 7
SSL_ERROR_WANT_ACCEPT  :: 8

// SSL verify modes
SSL_VERIFY_NONE :: 0x00
SSL_VERIFY_PEER :: 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT :: 0x02
SSL_VERIFY_CLIENT_ONCE :: 0x04

// SSL file type
SSL_FILETYPE_PEM :: 1

// SSL session cache
SSL_SESS_CACHE_OFF :: 0x0000

SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
SSL_CTRL_SET_READ_AHEAD :: 41

TLSEXT_NAMETYPE_host_name :: 0

// Cookie callbacks for DTLS stateless server
Cookie_Generate_Cb :: #type proc(ssl: ^SSL, cookie: [^]byte, cookie_len: ^c.uint) -> c.int
Cookie_Verify_Cb   :: #type proc(ssl: ^SSL, cookie: [^]byte, cookie_len: c.uint) -> c.int

foreign lib {
	TLS_client_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_write :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	ERR_print_errors_fp :: proc(fp: ^libc.FILE) ---
	SSL_ctrl :: proc(ssl: ^SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	OpenSSL_version_num :: proc() -> c.ulong ---

	// BIO (DTLS/UDP)
	BIO_new_dgram :: proc(fd: c.int, close_flag: c.int) -> ^BIO ---
	BIO_free :: proc(bio: ^BIO) -> c.int ---
	BIO_ctrl :: proc(bp: ^BIO, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	BIO_int_ctrl :: proc(bp: ^BIO, cmd: c.int, larg: c.long, iarg: c.int) -> c.long ---

	// DTLS
	DTLS_server_method :: proc() -> ^SSL_METHOD ---
	DTLS_client_method :: proc() -> ^SSL_METHOD ---
	// client: pass rawptr to sockaddr_storage (dtls_udp_echo pattern) or BIO_ADDR
	DTLSv1_listen :: proc(ssl: ^SSL, client: rawptr) -> c.int ---

	// SSL (DTLS/UDP)
	SSL_set_bio :: proc(ssl: ^SSL, rbio: ^BIO, wbio: ^BIO) ---
	SSL_accept :: proc(ssl: ^SSL) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_get_rbio :: proc(ssl: ^SSL) -> ^BIO ---
	SSL_get_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_set_options :: proc(ssl: ^SSL, op: c.ulong) -> c.ulong ---

	// SSL_CTX (cert, key, DTLS options)
	SSL_CTX_use_certificate_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_ctrl :: proc(ctx: ^SSL_CTX, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_CTX_set_cookie_generate_cb :: proc(ctx: ^SSL_CTX, cb: Cookie_Generate_Cb) ---
	SSL_CTX_set_cookie_verify_cb :: proc(ctx: ^SSL_CTX, cb: Cookie_Verify_Cb) ---
	SSL_CTX_set_verify :: proc(ctx: ^SSL_CTX, mode: c.int, callback: rawptr) ---
	SSL_CTX_set_verify_depth :: proc(ctx: ^SSL_CTX, depth: c.int) ---
	SSL_CTX_set_session_cache_mode :: proc(ctx: ^SSL_CTX, mode: c.int) -> c.int ---

	// ERR
	ERR_get_error :: proc() -> c.ulong ---
	ERR_error_string :: proc(e: c.ulong, buf: rawptr) -> cstring ---

	// RSA (data encrypt/decrypt, in libcrypto)
	RSA_public_encrypt  :: proc(flen: c.int, from: [^]byte, to: [^]byte, rsa: ^RSA, padding: c.int) -> c.int ---
	RSA_private_decrypt :: proc(flen: c.int, from: [^]byte, to: [^]byte, rsa: ^RSA, padding: c.int) -> c.int ---
	RSA_private_encrypt :: proc(flen: c.int, from: [^]byte, to: [^]byte, rsa: ^RSA, padding: c.int) -> c.int ---
	RSA_public_decrypt  :: proc(flen: c.int, from: [^]byte, to: [^]byte, rsa: ^RSA, padding: c.int) -> c.int ---
	RSA_size :: proc(rsa: ^RSA) -> c.int ---
	RSA_free :: proc(rsa: ^RSA) ---
	RSA_new :: proc() -> ^RSA ---
	RSA_generate_key_ex :: proc(rsa: ^RSA, bits: c.int, e: ^BIGNUM, cb: rawptr) -> c.int ---

	// BIGNUM for RSA_generate_key_ex exponent
	BN_new :: proc() -> ^BIGNUM ---
	BN_free :: proc(bn: ^BIGNUM) ---
	BN_set_word :: proc(a: ^BIGNUM, w: c.ulong) -> c.int ---

	// PEM / BIO for loading RSA keys (libcrypto)
	BIO_new_mem_buf :: proc(buf: rawptr, len: c.int) -> ^BIO ---
	BIO_new_file :: proc(filename: cstring, mode: cstring) -> ^BIO ---
	BIO_new :: proc(type: rawptr) -> ^BIO ---
	BIO_s_mem :: proc() -> rawptr ---
	BIO_read :: proc(b: ^BIO, data: rawptr, dlen: c.int) -> c.int ---
	PEM_write_bio_RSAPublicKey :: proc(bp: ^BIO, rsa: ^RSA) -> c.int ---
	PEM_read_bio_RSAPublicKey  :: proc(bp: ^BIO, x: ^^RSA, cb: rawptr, u: rawptr) -> ^RSA ---
	PEM_read_bio_RSAPrivateKey :: proc(bp: ^BIO, x: ^^RSA, cb: rawptr, u: rawptr) -> ^RSA ---
}

// This is a macro in c land.
SSL_set_tlsext_host_name :: proc(ssl: ^SSL, name: cstring) -> c.int {
	return c.int(SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)))
}

// BIO helpers (C macros)
BIO_set_fd :: proc(b: ^BIO, fd: c.int, close_flag: c.int) -> c.int {
	return c.int(BIO_int_ctrl(b, BIO_C_SET_FD, c.long(close_flag), fd))
}
BIO_ctrl_set_connected :: proc(b: ^BIO, peer: rawptr) -> c.int {
	return c.int(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, peer))
}
BIO_ctrl_set_recv_timeout :: proc(b: ^BIO, timeout: rawptr) -> c.int {
	return c.int(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, timeout))
}
BIO_dgram_recv_timedout :: proc(b: ^BIO) -> c.int {
	return c.int(BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, nil))
}
BIO_dgram_get_peer :: proc(b: ^BIO, peer: rawptr) -> c.int {
	return c.int(BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, peer))
}

SSL_CTX_set_read_ahead :: proc(ctx: ^SSL_CTX, m: c.int) {
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, c.long(m), nil)
}

// RSA helpers: load key from PEM string, encrypt with public key, decrypt with private key
RSA_load_public_pem :: proc(pem_data: string) -> ^RSA {
	if len(pem_data) == 0 do return nil
	data := transmute([]byte)pem_data
	bio := BIO_new_mem_buf(raw_data(data), c.int(len(data)))
	if bio == nil do return nil
	defer BIO_free(bio)
	return PEM_read_bio_RSAPublicKey(bio, nil, nil, nil)
}

RSA_load_private_pem :: proc(pem_data: string) -> ^RSA {
	if len(pem_data) == 0 do return nil
	data := transmute([]byte)pem_data
	bio := BIO_new_mem_buf(raw_data(data), c.int(len(data)))
	if bio == nil do return nil
	defer BIO_free(bio)
	return PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
}

RSA_load_public_pem_file :: proc(path: cstring) -> ^RSA {
	bio := BIO_new_file(path, "r")
	if bio == nil do return nil
	defer BIO_free(bio)
	return PEM_read_bio_RSAPublicKey(bio, nil, nil, nil)
}

RSA_load_private_pem_file :: proc(path: cstring) -> ^RSA {
	bio := BIO_new_file(path, "r")
	if bio == nil do return nil
	defer BIO_free(bio)
	return PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
}

// Encrypt data with public key. Returns encrypted length or -1 on error.
// out must be at least RSA_size(rsa) bytes.
RSA_encrypt :: proc(rsa: ^RSA, data: []byte, out: []byte, padding: c.int = RSA_PKCS1_PADDING) -> c.int {
	if rsa == nil || len(data) == 0 || len(out) < int(RSA_size(rsa)) do return -1
	return RSA_public_encrypt(c.int(len(data)), raw_data(data), raw_data(out), rsa, padding)
}

// Decrypt data with private key. Returns decrypted length or -1 on error.
// out must be at least RSA_size(rsa) bytes.
RSA_decrypt :: proc(rsa: ^RSA, data: []byte, out: []byte, padding: c.int = RSA_PKCS1_PADDING) -> c.int {
	if rsa == nil || len(data) == 0 || len(out) < int(RSA_size(rsa)) do return -1
	return RSA_private_decrypt(c.int(len(data)), raw_data(data), raw_data(out), rsa, padding)
}

RSA_F4 :: 0x10001

// Generate RSA key pair (2048 bits, exponent 65537). Caller must RSA_free the result.
RSA_generate_key :: proc(bits: c.int = 2048) -> ^RSA {
	rsa := RSA_new()
	if rsa == nil do return nil
	e := BN_new()
	if e == nil {
		RSA_free(rsa)
		return nil
	}
	defer BN_free(e)
	if BN_set_word(e, RSA_F4) != 1 {
		RSA_free(rsa)
		return nil
	}
	if RSA_generate_key_ex(rsa, bits, e, nil) != 1 {
		RSA_free(rsa)
		return nil
	}
	return rsa
}

// Export RSA public key as PEM string. Caller must delete the returned string.
RSA_export_public_pem :: proc(rsa: ^RSA, allocator := context.allocator) -> []byte {
	if rsa == nil do return nil
	bio := BIO_new(BIO_s_mem())
	if bio == nil do return nil
	defer BIO_free(bio)
	if PEM_write_bio_RSAPublicKey(bio, rsa) != 1 do return nil

	pending := BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
	if pending <= 0 do return nil

	buf := make([]byte, pending, allocator)
	n := BIO_read(bio, raw_data(buf), c.int(pending))
	if n <= 0 {
		delete(buf, allocator)
		return nil
	} 

	return buf
}

ERR_print_errors :: proc {
	ERR_print_errors_fp,
	ERR_print_errors_stderr,
}

ERR_print_errors_stderr :: proc() {
	ERR_print_errors_fp(libc.stderr)
}
