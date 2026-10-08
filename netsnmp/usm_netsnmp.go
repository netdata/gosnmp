// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

/*
#cgo LDFLAGS: -lnetsnmp
#include <stdlib.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>

// auth_oid returns net-snmp's OID for a gosnmp SnmpV3AuthProtocol value.
static oid *auth_oid(int proto, u_int *len) {
	switch (proto) {
	case 2: *len = OID_LENGTH(usmHMACMD5AuthProtocol); return usmHMACMD5AuthProtocol;
	case 3: *len = OID_LENGTH(usmHMACSHA1AuthProtocol); return usmHMACSHA1AuthProtocol;
	case 4: *len = OID_LENGTH(usmHMAC128SHA224AuthProtocol); return usmHMAC128SHA224AuthProtocol;
	case 5: *len = OID_LENGTH(usmHMAC192SHA256AuthProtocol); return usmHMAC192SHA256AuthProtocol;
	case 6: *len = OID_LENGTH(usmHMAC256SHA384AuthProtocol); return usmHMAC256SHA384AuthProtocol;
	case 7: *len = OID_LENGTH(usmHMAC384SHA512AuthProtocol); return usmHMAC384SHA512AuthProtocol;
	}
	return NULL;
}

// priv_oid returns net-snmp's OID and key extension type for a gosnmp
// SnmpV3PrivProtocol value. AES192C and AES256C are net-snmp's Cisco
// variants, which extend the key with Reeder's algorithm.
static oid *priv_oid(int proto, u_int *len, int *type) {
	switch (proto) {
	case 2: *len = OID_LENGTH(usmDESPrivProtocol); *type = USM_CREATE_USER_PRIV_DES; return usmDESPrivProtocol;
	case 3: *len = OID_LENGTH(usmAESPrivProtocol); *type = USM_CREATE_USER_PRIV_AES; return usmAESPrivProtocol;
	case 4: *len = OID_LENGTH(usmAES192PrivProtocol); *type = USM_CREATE_USER_PRIV_AES192; return usmAES192PrivProtocol;
	case 5: *len = OID_LENGTH(usmAES256PrivProtocol); *type = USM_CREATE_USER_PRIV_AES256; return usmAES256PrivProtocol;
	case 6: *len = OID_LENGTH(usmAES192CiscoPrivProtocol); *type = USM_CREATE_USER_PRIV_AES192_CISCO; return usmAES192CiscoPrivProtocol;
	case 7: *len = OID_LENGTH(usmAES256CiscoPrivProtocol); *type = USM_CREATE_USER_PRIV_AES256_CISCO; return usmAES256CiscoPrivProtocol;
	}
	return NULL;
}

// localize derives Ku from the passphrase and localizes it to the engine ID
// (RFC 3414 section 2.6).
static int localize(oid *hash, u_int hashlen, const u_char *pass, size_t passlen,
		const u_char *eid, size_t eidlen, u_char *kul, size_t *kullen) {
	u_char ku[USM_LENGTH_KU_HASHBLOCK];
	size_t kulen = sizeof(ku);
	int rc = generate_Ku(hash, hashlen, pass, passlen, ku, &kulen);
	if (rc != SNMPERR_SUCCESS)
		return rc;
	return generate_kul(hash, hashlen, eid, eidlen, ku, kulen, kul, kullen);
}

// priv_key localizes the privacy passphrase with the authentication hash and
// extends the result to the cipher's key length as net-snmp does for a user.
static int priv_key(int auth, int priv, const u_char *pass, size_t passlen,
		u_char *eid, size_t eidlen, u_char *key, size_t *keylen) {
	u_int hashlen, privlen;
	int type;
	oid *hash = auth_oid(auth, &hashlen);
	oid *privoid = priv_oid(priv, &privlen, &type);
	if (hash == NULL || privoid == NULL)
		return SNMPERR_GENERR;

	int rc = localize(hash, hashlen, pass, passlen, eid, eidlen, key, keylen);
	if (rc != SNMPERR_SUCCESS)
		return rc;

	int need = sc_get_proper_priv_length(privoid, privlen);
	rc = netsnmp_extend_kul(need, hash, hashlen, type, eid, eidlen, &key, keylen, USM_LENGTH_KU_HASHBLOCK);
	// Keep only what the cipher uses; DES also uses the pre-IV in the
	// 8 octets after its key (RFC 3414 section 8.1.1.1).
	if (type == USM_CREATE_USER_PRIV_DES)
		need = 16;
	if (rc == SNMPERR_SUCCESS && *keylen > (size_t)need)
		*keylen = need;
	return rc;
}

static int auth_key(int auth, const u_char *pass, size_t passlen,
		const u_char *eid, size_t eidlen, u_char *key, size_t *keylen) {
	u_int hashlen;
	oid *hash = auth_oid(auth, &hashlen);
	if (hash == NULL)
		return SNMPERR_GENERR;
	return localize(hash, hashlen, pass, passlen, eid, eidlen, key, keylen);
}

static int keyed_hash(int auth, const u_char *key, u_int keylen,
		const u_char *msg, u_int msglen, u_char *mac, size_t *maclen) {
	u_int hashlen;
	oid *hash = auth_oid(auth, &hashlen);
	if (hash == NULL)
		return SNMPERR_GENERR;
	*maclen = sc_get_auth_maclen(sc_get_authtype(hash, hashlen));
	return sc_generate_keyed_hash(hash, hashlen, key, keylen, msg, msglen, mac, maclen);
}

static int encrypt(int priv, u_char *key, u_int keylen, u_char *iv, u_int ivlen,
		u_char *pt, size_t ptlen, u_char *ct, size_t *ctlen) {
	u_int privlen;
	int type;
	oid *privoid = priv_oid(priv, &privlen, &type);
	if (privoid == NULL)
		return SNMPERR_GENERR;
	return sc_encrypt(privoid, privlen, key, keylen, iv, ivlen, pt, ptlen, ct, ctlen);
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/netdata/gosnmp"
)

// usmKeyBufSize is net-snmp's localized key buffer size, enough for SHA-512
// and every key extension.
const usmKeyBufSize = C.USM_LENGTH_KU_HASHBLOCK

func netSnmpAuthKey(auth gosnmp.SnmpV3AuthProtocol, passphrase, engineID string) ([]byte, error) {
	pass, eid := cBytes(passphrase), cBytes(engineID)
	defer C.free(pass)
	defer C.free(eid)

	key := C.malloc(usmKeyBufSize)
	defer C.free(key)
	keylen := C.size_t(usmKeyBufSize)
	if rc := C.auth_key(C.int(auth), (*C.u_char)(pass), C.size_t(len(passphrase)),
		(*C.u_char)(eid), C.size_t(len(engineID)), (*C.u_char)(key), &keylen); rc != C.SNMPERR_SUCCESS {
		return nil, fmt.Errorf("net-snmp: localizing the %v key: error %d", auth, rc)
	}
	return C.GoBytes(key, C.int(keylen)), nil
}

func netSnmpPrivKey(auth gosnmp.SnmpV3AuthProtocol, priv gosnmp.SnmpV3PrivProtocol, passphrase, engineID string) ([]byte, error) {
	pass, eid := cBytes(passphrase), cBytes(engineID)
	defer C.free(pass)
	defer C.free(eid)

	key := C.malloc(usmKeyBufSize)
	defer C.free(key)
	keylen := C.size_t(usmKeyBufSize)
	if rc := C.priv_key(C.int(auth), C.int(priv), (*C.u_char)(pass), C.size_t(len(passphrase)),
		(*C.u_char)(eid), C.size_t(len(engineID)), (*C.u_char)(key), &keylen); rc != C.SNMPERR_SUCCESS {
		return nil, fmt.Errorf("net-snmp: localizing the %v/%v key: error %d", auth, priv, rc)
	}
	return C.GoBytes(key, C.int(keylen)), nil
}

func netSnmpHMAC(auth gosnmp.SnmpV3AuthProtocol, key, msg []byte) ([]byte, error) {
	k, m := cBytes(string(key)), cBytes(string(msg))
	defer C.free(k)
	defer C.free(m)

	mac := C.malloc(usmKeyBufSize)
	defer C.free(mac)
	var maclen C.size_t
	if rc := C.keyed_hash(C.int(auth), (*C.u_char)(k), C.u_int(len(key)),
		(*C.u_char)(m), C.u_int(len(msg)), (*C.u_char)(mac), &maclen); rc != C.SNMPERR_SUCCESS {
		return nil, fmt.Errorf("net-snmp: %v HMAC: error %d", auth, rc)
	}
	return C.GoBytes(mac, C.int(maclen)), nil
}

func netSnmpEncrypt(priv gosnmp.SnmpV3PrivProtocol, key, iv, plaintext []byte) ([]byte, error) {
	k, v, p := cBytes(string(key)), cBytes(string(iv)), cBytes(string(plaintext))
	defer C.free(k)
	defer C.free(v)
	defer C.free(p)

	// DES pads to the next block; nothing else grows.
	ctcap := len(plaintext) + 8
	ct := C.malloc(C.size_t(ctcap))
	defer C.free(ct)
	ctlen := C.size_t(ctcap)
	if rc := C.encrypt(C.int(priv), (*C.u_char)(k), C.u_int(len(key)), (*C.u_char)(v), C.u_int(len(iv)),
		(*C.u_char)(p), C.size_t(len(plaintext)), (*C.u_char)(ct), &ctlen); rc != C.SNMPERR_SUCCESS {
		return nil, fmt.Errorf("net-snmp: %v encryption: error %d", priv, rc)
	}
	return C.GoBytes(ct, C.int(ctlen)), nil
}

// cBytes copies s into C memory, which the caller frees. Unlike C.CString it
// keeps NUL bytes and never returns NULL for empty input.
func cBytes(s string) unsafe.Pointer {
	p := C.malloc(C.size_t(len(s) + 1))
	copy(unsafe.Slice((*byte)(p), len(s)+1), s)
	return p
}
