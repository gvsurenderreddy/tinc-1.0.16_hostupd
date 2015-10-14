/*
    protocol_hostsupdate.c -- handle the host and conf file updates inside the protocol
    Copyright (C) 1998-2005 Ivo Timmermans,
		  2000-2010 Guus Sliepen <guus@tinc-vpn.org>
		  2015 LynxLynx <lynx@lynxlynx.tk>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/*
 * About this update subsystem.
 *
 * This subsystem introduces hosts and configuration automatic update facility
 * inside tinc protocol itself, so it can run:
 * 1) Distributed (with signatures)
 * 2) Asynchronously (at any time, even interferences are permitted)
 * 3) Updater servers can be added or removed at any time by updaters
 * 4) Not depends from external services: runs purely inside tinc network itself!
 *
 * For it to work, network admins should define special nodes which will be
 * responsible for update service they will run. The update service is inside tinc,
 * and updates are spread across the whole network via broadcast requests.
 *
 * Each update session will deliver the whole network hosts files to each node,
 * including master update nodes, so network consistency is maintained automatically.
 *
 * Receiving node can decide to receive updates or to ignore them.
 * If receiving node has child connections not connected directly with master node, it
 * can decide to forward update requests to them or not.
 *
 * Currently, this extension does not require all nodes to obey updates, but network consistency
 * is well maintained only when all nodes apply updates.
 *
 * To protect network consistency, not any node can send updates.
 * Only authorized nodes can do so. The authorization is granted from already
 * existing updater nodes, via these distributed hosts files updates.
 * If no node was defined as updater node, without external configuration file
 * edits on each node it's not possible to define one.
 * Selfnamed as updater nodes will be ignored by the rest of the network.
 * Information about updater nodes such as options, flags, or privilege marks is not
 * sent across network within control requests, instead, status of node privilege
 * is determined directly by reading it's host definition directly at each request.
 *
 * To prevent update request tampering, each request from authorized node is signed by
 * it's private key and signature is sent in each update request, be it control or data request.
 * When receiving, receive node tests it's privilege status from it's host definition and
 * tests signature of received request by verifying it with authorized node public key.
 *
 * IMPLEMENTATION DETAILS
 *
 * The protocol is extended by two new request types: HOSTUPDATE and CONFUPDATE.
 *
 * HOSTUPDATE request format:
 *
 * "HOSTUPDATE updname hosttoupd b64host slen dlen b64dgst"
 * HOSTUPDATE is request number (as all requests in tinc protocol) from request_t enum
 * updname is updater's authorized node name
 * hosttoupd is host name to be updated
 * b64host is base64 unencrypted host data to be overwritten
 * slen is length of decoded b64host
 * dlen is digital signature length (with sha256 it always 256)
 * b64dgst is base64 encoded request signature of "updname hosttoupd b64host slen",
 *	 to ensure consistency and prevent tampering
 *
 * HOSTUPDATE control requests
 *
 * Hosts update process starts with "START" HOSTUPDATE request:
 * "HOSTUPDATE updname updname START 0 dlen"
 * START is marker of started "session", but this process is now defined sessionless,
 *	because each receiver needs to run pre-update script, like embedded devices make
 *	their read-only filesystems read-write.
 * hosttoupd is set as updname, and receiver should check that
 * Length of host data is set to zero
 *
 * Hosts update process ends with "END" HOSTUPDATE request:
 * "HOSTUPDATE updname updname END 0 dlen"
 * It's like "START" request, but reverse. Usually when receiver gets this request, it runs
 * post-update script then schedules complete reload of tinc daemon to make changes effective.
 * All checks necessary for "START" request apply here.
 *
 * Inactive/dead/banned hosts are removed by HOSTUPDATE "DEAD" request:
 * "HOSTUPDATE updname hosttoupd DEAD 0 dlen"
 * On this request, receiver should remove hosttoupd file from it's hosts directory.
 * No necessary checks are defined for this host update.
 *
 * The similar request type is CONFUPDATE request. It is designed to update main configuration
 * file of the node, tinc.conf.
 * Few words about update process of file itself:
 * Since that each node configuration is rather individual, certain configuration variables
 * in which change we're not interested are preserved, and template "update" is appended then.
 *
 * CONFUPDATE request format:
 *
 * "CONFUPDATE updname b64conf slen dlen b64dgst"
 * CONFUPDATE is request number like in HOSTUPDATE
 * updname is updater's authorized node name
 * b64conf is base64 unencrypted configuration data to append
 * slen is length of base64 decoded configuration data
 * dlen is digital signature length (with sha256 it always 256)
 * b64dgst is base64 encoded signature of "updname b64conf slen dlen"
 *
 * CONFUPDATE request has the same START and END markers which are useful for scripts.
 *
 * END USER CONFIGURATION
 *
 * To define master nodes, each node must have one of these variables inside master node host file:
 *
 * "HostsFilesMaster" = yes | no - permits master node to send updates for
 *	 whole hosts files database
 * "ConfFileMaster" = yes | no - also to hosts files,
 *	master node can send updates for configuration file
 *
 * Master node configuration (tinc.conf):
 *
 * "HostsUpdateInterval" = seconds (0) - time between sending updates.
 *	Both hosts and conf updates are sent (if permissions are given)
 * "ConfFileTemplate" = filename - which file is template to send over as tinc.conf update
 *	(must be in directory with tinc.conf itself)
 *
 * Ignoring/forwarding updates policy (tinc.conf):
 *
 * "IgnoreHostsUpdates" = yes | no (no) - completely reject hosts updates.
 * "DontForwardHostsUpdates" = yes | no (no) - do not forward hosts updates
 *	to child nodes, but accept them.
 * "IgnoreConfUpdates" = yes | no (no) - completely reject configuration file updates.
 * "DontForwardConfUpdates" = yes | no (no) - do not forward configuration file updates
 *	 to child nodes, but accept them.
 * "IgnoreNetUpdates" = yes | no (no) - rejects all types of updates.
 * When ignoring updates, no answers about that is sent by ignoring nodes.
 *
 * Dead host marking and removing:
 *
 * "DeadHost" = yes | no - set in host file of host to be removed
 *	(the host file can be kept in hosts directory on master node, it will not be removed)
 *
 * Authentication tests (tinc.conf):
 *
 * "DontVerifyUpdateSignature" = yes | no (no) - bypass signature test
 * "DontVerifyUpdatePermission" = yes | no (no) - bypass permission test
 *
 * These are useful when you need to bootstrap full hosts database, when you don't have
 *	master node(s) hosts file with public key.
 * Note however network admins can set a config template to unset these vars when you're
 *	successfully bootstrapped your node, but anyone can send you random data in this mode
 *	(possibly with claims of their own authority) and you will happily accept that.
 *	Instead of this mode, you should already have received trustful bootstrap nodes
 *	information upon joining the network via other channels (email, ssh, https etc.)
 * To turn off all rights tests, you need to set both variables to yes.
 *
 * RUNNING PRE AND POST UPDATE SCRIPT
 *
 * When hosts files database is updated, the following scripts are executed as subprocess:
 *
 * hostsupdate-before, hostsupdate-after
 *
 * They are useful to prepare environment for writing updated files.
 * As an example, embedded systems with readonly remountable filesystems.
 *
 * When config file is updated, the following scripts are executed as subprocess:
 *
 * confupdate-before, confupdate-after
 *
 * Their purpose is same as host file scripts.
 *
 * "-before" script executed before update process is started, "-after" script executed after
 *	update process is ended.
 *
 * For all of those scripts the following environment variables are available:
 *
 * NETNAME, DEVICE, INTERFACE, NAME
 *
 * - Lynx, Oct2015
 */

#include "system.h"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "avl_tree.h"
#include "connection.h"
#include "logger.h"
#include "device.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"
#include "process.h"
#include "base64.h"

/* musl/src/string/strcasestr.c Copyright (C) 2005-2014 Rich Felker, et al. License: MIT */
char *strcasestr_local(const char *h, const char *n) {
	size_t l = strlen(n);
	for (; *h; h++) if (!strncasecmp(h, n, l)) return (char *)h;
	return 0;
}
/* !musl/src/string/strcasestr.c */

static void schedulereload(void) {
	/* TODO: configurable delay? */
	schedreload = now + 2;
}

static void run_script(const char *scriptname) {
	char *envp[5];
	int x;

	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script(scriptname, envp);

	for (x = 0; x < 4; x++) free(envp[x]);
}

/* Answering these questions right is tricky... */
static bool getconf_bool_node_offline(const char *nodename, char *optname) {
	char *fname;
	avl_tree_t *t;
	bool x;

	init_configuration(&t);

	xasprintf(&fname, "%s/hosts/%s", confbase, nodename);

	read_config_options(t, nodename);
	x = read_config_file(t, fname);
	if (!x) goto _end;

	if (!get_config_bool(lookup_config(t, optname), &x)) x = false;

_end:	exit_configuration(&t);
	free(fname);

	return x;
}

/* Well, almost clean copy of read_rsa_public_key */
static bool read_rsa_public_key_offline(const char *nodename, RSA **outkey) {
	avl_tree_t *t;
	FILE *fp;
	char *tname, *fname;
	char *key;
	bool x;
	RSA *rsa_key = NULL;

	init_configuration(&t);
	xasprintf(&tname, "%s/hosts/%s", confbase, nodename);
	x = read_config_file(t, tname);
	if (!x) goto _fail;

	if(!rsa_key) {
		rsa_key = RSA_new();
//		RSA_blinding_on(c->rsa_key, NULL);
	}

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(t, "PublicKey"), &key)) {
		BN_hex2bn(&rsa_key->n, key);
		BN_hex2bn(&rsa_key->e, "FFFF");
		free(key);
		*outkey = rsa_key;
		goto _done;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(get_config_string(lookup_config(t, "PublicKeyFile"), &fname)) {
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s",
				   fname, strerror(errno));
			free(fname);
			goto _fail;
		}

		free(fname);
		rsa_key = PEM_read_RSAPublicKey(fp, &rsa_key, NULL, NULL);
		fclose(fp);

		if(rsa_key) {
			*outkey = rsa_key;
			goto _done;		/* Woohoo. */
		}

		/* If it fails, try PEM_read_RSA_PUBKEY. */
		fp = fopen(fname, "r");

		if(!fp) {
			logger(LOG_ERR, "Error reading RSA public key file `%s': %s",
				   fname, strerror(errno));
			free(fname);
			goto _fail;
		}

		free(fname);
		rsa_key = PEM_read_RSA_PUBKEY(fp, &rsa_key, NULL, NULL);
		fclose(fp);

		if(rsa_key) {
//				RSA_blinding_on(c->rsa_key, NULL);
			*outkey = rsa_key;
			goto _done;
		}

		logger(LOG_ERR, "Reading RSA public key file `%s' failed: %s",
			   fname, strerror(errno));
		goto _fail;
	}

	/* Else, check if a harnessed public key is in the config file */

	xasprintf(&fname, "%s/hosts/%s", confbase, nodename);
	fp = fopen(fname, "r");

	if(fp) {
		rsa_key = PEM_read_RSAPublicKey(fp, &rsa_key, NULL, NULL);
		fclose(fp);
	}

	free(fname);

	if(rsa_key) {
		*outkey = rsa_key;
		goto _done;
	}

	/* Try again with PEM_read_RSA_PUBKEY. */

	xasprintf(&fname, "%s/hosts/%s", confbase, nodename);
	fp = fopen(fname, "r");

	if(fp) {
		rsa_key = PEM_read_RSA_PUBKEY(fp, &rsa_key, NULL, NULL);
//		RSA_blinding_on(c->rsa_key, NULL);
		fclose(fp);
	}

	free(fname);

	if(rsa_key) {
		*outkey = rsa_key;
		goto _done;
	}

	logger(LOG_ERR, "No public key for %s specified!", nodename);

_fail:	
	exit_configuration(&t);
	free(tname);
	return false;

_done:	
	exit_configuration(&t);
	free(tname);
	return true;
}

static void EVP_sign(RSA *rsa, const char *data, size_t l, char *outsig, size_t *sigl) {
	EVP_MD_CTX ctx;
	EVP_PKEY *pkey;

	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, rsa);

	EVP_SignInit(&ctx, EVP_sha256());
	EVP_SignUpdate(&ctx, data, l);
	EVP_SignFinal(&ctx, outsig, sigl, pkey);

	EVP_PKEY_free(pkey);
}

static bool EVP_verify(RSA *rsa, const char *sign, size_t sigl, const char *data, size_t l) {
	EVP_MD_CTX ctx;
	EVP_PKEY *pkey;
	bool ret = false;

	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, rsa);

	EVP_VerifyInit(&ctx, EVP_sha256());
	EVP_VerifyUpdate(&ctx, data, l);
	if (EVP_VerifyFinal(&ctx, sign, sigl, pkey) == 1) ret = true;

	EVP_PKEY_free(pkey);

	return ret;
}

void send_hostsstartendupdate(int start) {
	char rawhost[MAX_STRING_SIZE];
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];
	size_t slen, dlen, rlen;
	bool choice;

	/* test if we're are authorized to broadcast the data */
	if(get_config_bool(lookup_config(config_tree, "HostsFilesMaster"), &choice) && !choice) {
		return;
	}

	/* Start update session */
	dlen = RSA_size(myself->connection->rsa_key);
	if (dlen > sizeof(rawdgst)/2) {
		logger(LOG_ERR, "Could not start hosts update session due to digest overflow");
		return;
	}

	snprintf(rawhost, sizeof(rawhost), "%s %s %s 0 %d",
		myself->name, myself->name, start ? "START" : "END", dlen);
	rlen = strlen(rawhost);
	EVP_sign(myself->connection->rsa_key, rawhost, rlen, rawdgst, &dlen);
	if (base64_enclen(dlen) >= MAX_STRING_SIZE) {
		logger(LOG_ERR,
		"Could not %s hosts update session, base64 digest overflow",
		start ? "start" : "end");

		return;
	}
	base64_encode(rawdgst, dlen, b64dgst, sizeof(b64dgst)-1);
	send_request(broadcast, "%d %s %s", HOSTUPDATE, rawhost, b64dgst);
}

void send_hostsupdates(void) {
	/* FIXME: Too memory hungry */
	char rawfile[MAX_STRING_SIZE];
	char rawhost[MAX_STRING_SIZE], b64host[MAX_STRING_SIZE];
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];

	char *fname, *dname;
	struct stat s;
	DIR *dir; FILE *fp;
	struct dirent *ent;
	size_t slen, dlen, rlen;
	bool choice;

	/* test if we're are authorized to broadcast the data */
	if(get_config_bool(lookup_config(config_tree, "HostsFilesMaster"), &choice) && !choice) {
		return;
	}

	dlen = RSA_size(myself->connection->rsa_key);
	if (dlen > sizeof(rawdgst)/2) {
		logger(LOG_ERR, "Could not send hosts updates due to digest overflow");
		return;
	}

	/* broadcast complete host data as is (as on disk) we own */
	xasprintf(&dname, "%s/hosts", confbase);
	dir = opendir(dname);
	free(dname);
	if(!dir) return;

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		xasprintf(&fname, "%s/hosts/%s", confbase, ent->d_name);

		fp = fopen(fname, "r");
		if (!fp) {
			logger(LOG_ERR, "Could not open host file %s: %s", fname, strerror(errno));
			free(fname);
			continue;
		}
		slen = fread(rawfile, 1, sizeof(rawfile), fp);
		fclose(fp);

		if (base64_enclen(slen) >= MAX_STRING_SIZE) {
			logger(LOG_WARNING, "Host file %s too long to send", fname);
			free(fname);
			continue;
		}
		base64_encode(rawfile, slen, b64host, sizeof(b64host)-1);

		snprintf(rawhost, sizeof(rawhost), "%s %s %s %d %d",
			myself->name, ent->d_name, b64host, slen, dlen);
		
		rlen = strlen(rawhost);
		EVP_sign(myself->connection->rsa_key, rawhost, rlen, rawdgst, &dlen);	
		if (base64_enclen(dlen) >= MAX_STRING_SIZE) {
			logger(LOG_WARNING, "Digest for host file %s too long to send", fname);
			free(fname);
			continue;
		}
		base64_encode(rawdgst, dlen, b64dgst, sizeof(b64dgst)-1);

		send_request(broadcast, "%d %s %s", HOSTUPDATE, rawhost, b64dgst);
		free(fname);
	}

	closedir(dir);

	/* Again, but for "dead" hosts */
	xasprintf(&dname, "%s/hosts", confbase);
	dir = opendir(dname);
	free(dname);
	if(!dir) return;

	/* send a list of dead hosts */
	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		if(getconf_bool_node_offline(ent->d_name, "DeadHost")) {
			snprintf(rawhost, sizeof(rawhost), "%s %s DEAD 0 %d",
				myself->name, ent->d_name, dlen);
			rlen = strlen(rawhost);
			EVP_sign(myself->connection->rsa_key, rawhost, rlen, rawdgst, &dlen);
			if (base64_enclen(dlen) >= MAX_STRING_SIZE) {
				logger(LOG_ERR, "Digest for dead host file %s too long to send",
					ent->d_name);
				continue;
			}
			base64_encode(rawdgst, dlen, b64dgst, sizeof(b64dgst)-1);
			send_request(broadcast, "%d %s %s", HOSTUPDATE, rawhost, b64dgst);
		}
	}

	closedir(dir);
}

static bool isvalidfname(const char *name) {
	/* TODO: more paranoid checks... */
	if(strstr(name, "..")) return false;
	if(!check_id(name)) return false;
	return true;
}

static bool dontverifyupdatesignature(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "DontVerifyUpdateSignature"),
		&flag) && flag)
		return true;
	else
		return false;
}

static bool dontverifyupdatepermission(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "DontVerifyUpdatePermission"),
		&flag) && flag)
		return true;
	else
		return false;
}

/* Riot against the system! */
static bool ignorenetupdates(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "IgnoreNetUpdates"), &flag) && flag)
		return true;
	else
		return false;
}

static bool ignorehostsupdates(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "IgnoreHostsUpdates"), &flag) && flag)
		return true;
	else
		return false;
}

static bool dontforwardhostsupdates(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "DontForwardHostsUpdates"), &flag) && flag)
		return true;
	else
		return false;
}

bool hostupdate_h(connection_t *c) {
	/* FIXME: Whoah! Even more!! */
	char rawfile[MAX_STRING_SIZE];
	char rawhost[MAX_STRING_SIZE], b64host[MAX_STRING_SIZE];
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];
	char updname[MAX_STRING_SIZE], hosttoupd[MAX_STRING_SIZE];
	char *fname;
	FILE *fp;
	size_t slen, dlen, rlen;
	static RSA *updkey;

	if (updkey) { RSA_free(updkey); updkey = NULL; }

	/* We ignore host files updates, maybe for reason */
	if (ignorenetupdates() || ignorehostsupdates()) return true;

	/* handle received host data, check sign, (over)write on disk */
	if (sscanf(c->buffer, "%*d " MAX_STRING " " MAX_STRING " " MAX_STRING " %d %d " MAX_STRING,
		updname, hosttoupd, b64host, &slen, &dlen, b64dgst) != 6) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "HOSTUPDATE", c->name, c->hostname);
		return false;
	}

	if (!isvalidfname(updname)) {
		logger(LOG_ERR,
		"Got bogus updater name \"%s\" from %s (%s) (from: %s)",
		updname, c->name, c->hostname, updname);

		return false;
	}

	if (slen >= MAX_STRING_SIZE || dlen >= MAX_STRING_SIZE) {
		logger(LOG_ERR,
		"HOSTUPDATE string sizes for %s are bigger than buffer can fit (%d, %d)",
		hosttoupd, slen, dlen);

		return false;
	}

	/* verify it */
	if (dontverifyupdatesignature()) goto _next;
	if (!read_rsa_public_key_offline(updname, &updkey)) {
		logger(LOG_ERR, "Could not find public key for %s", updname);
		return true;
	}
	base64_decode(b64dgst, rawdgst, sizeof(rawdgst)-1);
	snprintf(rawhost, sizeof(rawhost), "%s %s %s %d %d", updname, hosttoupd, b64host, slen, dlen);
	rlen = strlen(rawhost);
	if (!EVP_verify(updkey, rawdgst, dlen, rawhost, rlen)) {
		logger(LOG_WARNING,
		"Ignoring hosts update request with bad signature from %s for %s"
		" [which came from %s (%s)]",
		updname, hosttoupd, c->name, c->hostname);

		return true;
	}

	/* verify the originating node is permitted to send updates */
_next:	if (dontverifyupdatepermission()) goto _out;
	if(!getconf_bool_node_offline(updname, "HostsFilesMaster")) {
		logger(LOG_WARNING,
		"Ignoring hosts update request originating from %s [which came from %s (%s)]",
		updname, c->name, c->hostname);

		return true;
	}

	/* some other sanity checks */
_out:	if (!isvalidfname(hosttoupd)) {
		logger(LOG_ERR,
		"Got bogus update name \"%s\" from %s (%s) (from: %s)",
		hosttoupd, c->name, c->hostname, updname);

		return false;
	}

	/* All right, let's start updating */

	xasprintf(&fname, "%s/hosts/%s", confbase, hosttoupd);

	/* Tell others if needed */
	if (!dontforwardhostsupdates()) forward_request(c);

	/* Check if it's a START marker */
	if (!strcmp(updname, hosttoupd) && !strcmp(b64host, "START")) {
		/* Run pre-update script (embedded devices do remount,rw fs for example)
		 We really need to run this once, so that's why there are START and END markers */
		run_script("hostsupdate-before");
		/* That's it folks! Waiting for files to arrive */
		free(fname);
		return true;
	}

	/* Check if it's a END marker */
	else if (!strcmp(updname, hosttoupd) && !strcmp(b64host, "END")) {
		/* Run post-update script (embedded devices do remount,ro fs for example) */
		run_script("hostsupdate-after");

		/* Schedule config/host reload */
		schedulereload();

		/* That's it folks! */
		free(fname);
		return true;
	}

	/* Remove unneeded hosts */
	else if (!strcmp(b64host, "DEAD")) {
		unlink(fname);
		/* That's it, waiting for other next request */
		free(fname);
		return true;
	}

	/* We need this early for next test */
	base64_decode(b64host, rawhost, sizeof(rawhost)-1);

	/*
	 * Via broadcasting host files one hosts file master can become config file master.
	 * Reject such a claims even if they're authentic.
	 */
	if (dontverifyupdatepermission()) goto _write;
	if(!getconf_bool_node_offline(updname, "ConfFileMaster")
		&& strcasestr_local(rawhost, "ConfFileMaster")) {
		logger(LOG_WARNING,
		"Ignoring %s which tried to raise privileges for %s to ConfFileMaster!",
		updname, hosttoupd);

		goto _end;
	}

	/* Finally write it to disk */
_write:	fp = fopen(fname, "w");
	if (!fp) {
		logger(LOG_ERR, "Unable to write new host file: %s (%s)", fname, strerror(errno));
		free(fname);
		return true;
	}
#ifndef HAVE_MINGW
	fchmod(fileno(fp), 0640); /* TODO: configurable? */
#endif

	fwrite(rawhost, slen, 1, fp);
	fclose(fp);

_end:
	free(fname);
	return true;
}

void send_confstartendupdate(int start) {
	char rawconf[MAX_STRING_SIZE];
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];
	size_t slen, dlen, rlen;
	char *fname;
	bool choice;

	/* test if we're are authorized to broadcast the data */
	if(get_config_bool(lookup_config(config_tree, "ConfFileMaster"), &choice) && !choice) {
		return;
	}

	if(get_config_string(lookup_config(config_tree, "ConfFileTemplate"), &fname)) free(fname);
	else return;

	/* Start update session */
	dlen = RSA_size(myself->connection->rsa_key);
	if (dlen > sizeof(rawdgst)/2) {
		logger(LOG_ERR, "Could not start config update session due to digest overflow");
		return;
	}

	snprintf(rawconf, sizeof(rawconf), "%s %s 0 %d",
		myself->name, start ? "START" : "END", dlen);
	rlen = strlen(rawconf);
	EVP_sign(myself->connection->rsa_key, rawconf, rlen, rawdgst, &dlen);
	if (base64_enclen(dlen) >= MAX_STRING_SIZE) {
		logger(LOG_ERR,
		"Could not %s config update session, base64 digest overflow",
		start ? "start" : "end");

		return;
	}
	base64_encode(rawdgst, dlen, b64dgst, sizeof(b64dgst)-1);
	send_request(broadcast, "%d %s %s", CONFUPDATE, rawconf, b64dgst);
}

/* Pretty same as hosts, but only for one file */
void send_confupdate(void) {
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];
	char rawconf[MAX_STRING_SIZE], b64conf[MAX_STRING_SIZE];
	char *fname, *tname;
	FILE *fp;
	size_t slen, dlen, rlen;
	bool choice;

	if(get_config_bool(lookup_config(config_tree, "ConfFileMaster"), &choice) && !choice) {
		return;
	}

	dlen = RSA_size(myself->connection->rsa_key);
	if (dlen > sizeof(rawdgst)/2) {
		logger(LOG_ERR, "Could not send config update due to digest overflow");
		return;
	}

	if(get_config_string(lookup_config(config_tree, "ConfFileTemplate"), &fname)
	&& ((strcmp(fname, "tinc.conf") != 0) && (strcmp(fname, "rsa_key.priv") != 0))) {
		dlen = RSA_size(myself->connection->rsa_key);
		if (dlen > sizeof(rawdgst)/2) {
			logger(LOG_ERR,"Could not start config update session due to digest overflow");
			free(fname);
			return;
		}
	
		xasprintf(&tname, "%s/%s", confbase, fname);
		fp = fopen(tname, "r");
		if (!fp) {
			logger(LOG_ERR, "Could not open ConfFileTemplate %s and send it!", tname);
			free(tname);
			free(fname);
			return;
		}
		slen = fread(rawconf, 1, sizeof(rawconf), fp);

		fclose(fp);

		if (base64_enclen(slen) >= MAX_STRING_SIZE) {
			logger(LOG_ERR, "Config data %s is too long to base64 encode", tname);
			free(tname);
			free(fname);
			return;
		}
		base64_encode(rawconf, slen, b64conf, sizeof(b64conf)-1);

		snprintf(rawconf, sizeof(rawconf), "%s %s %d %d",
			myself->name, b64conf, slen, dlen);

		free(tname);
		free(fname);

		rlen = strlen(rawconf);
		EVP_sign(myself->connection->rsa_key, rawconf, rlen, rawdgst, &dlen);
		if (base64_enclen(dlen) >= MAX_STRING_SIZE) {
			logger(LOG_ERR, "Could not sign config update, base64 digest overflow");
			return;
		}
		base64_encode(rawdgst, dlen, b64dgst, sizeof(b64dgst)-1);

		send_request(broadcast, "%d %s %s", CONFUPDATE, rawconf, b64dgst);
	}
}

static bool ignoreconfupdates(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "IgnoreConfUpdates"), &flag) && flag)
		return true;
	else
		return false;
}

static bool dontforwardconfupdates(void) {
	bool flag = false;

	if (get_config_bool(lookup_config(config_tree, "DontForwardConfUpdates"), &flag) && flag)
		return true;
	else
		return false;
}

/* The list of tinc.conf variables in which we are not interested */
static char (*confvarstopreserve[]) = {
	"Name", "PrivateKey", "PrivateKeyFile", "Device", "Interface",
	"AddressFamily", "BindToAddress", "BindToInterface", "DeviceType",
	"Mode", "ProcessPriority", "Proxy", "TunnelServer", "UDPRcvBuf", "UDPSndBuf",
	NULL
};

bool confupdate_h(connection_t *c) {
	char updname[MAX_STRING_SIZE];
	char rawconf[MAX_STRING_SIZE], b64conf[MAX_STRING_SIZE];
	char rawdgst[MAX_STRING_SIZE], b64dgst[MAX_STRING_SIZE];
	node_t *n;
	char *fname, *tname;
	FILE *fp;
	int x;
	size_t slen, dlen, rlen;
	static RSA *updkey;

	if (updkey) { RSA_free(updkey); updkey = NULL; }

	/* Guard ourselves against updates */
	if (ignorenetupdates() || ignoreconfupdates()) return true;

	if (sscanf(c->buffer, "%*d " MAX_STRING " " MAX_STRING " %d %d " MAX_STRING,
		updname, b64conf, &slen, &dlen, b64dgst) != 5) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "CONFUPDATE", c->name, c->hostname);
		return false;
	}

	if (!isvalidfname(updname)) {
		logger(LOG_ERR, "Got bogus updater name \"%s\" from %s (%s) (from: %s)",
			updname, c->name, c->hostname, updname);
		return false;
	}

	if (slen >= MAX_STRING_SIZE || dlen >= MAX_STRING_SIZE) {
		logger(LOG_ERR,
		"CONFUPDATE string sizes are bigger than buffer can fit (%d, %d)",
		slen, dlen);

		return false;
	}

	if (dontverifyupdatesignature()) goto _next;
	if (!read_rsa_public_key_offline(updname, &updkey)) {
		logger(LOG_ERR, "Could not find public key for %s", updname);
		return true;
	}
	base64_decode(b64dgst, rawdgst, sizeof(rawdgst)-1);
	snprintf(rawconf, sizeof(rawconf), "%s %s %d %d", updname, b64conf, slen, dlen);
	rlen = strlen(rawconf);
	if (!EVP_verify(updkey, rawdgst, dlen, rawconf, rlen)) {
		logger(LOG_WARNING,
		"Ignoring config update request with bad signature"
		" from %s [which came from %s (%s)]",
		updname, c->name, c->hostname);

		return true;
	}

_next:	if (dontverifyupdatepermission()) goto _out;
	if(!getconf_bool_node_offline(updname, "ConfFileMaster")) {
		logger(LOG_WARNING,
		"Ignoring config update request originating from %s [which came from %s (%s)]",
		updname, c->name, c->hostname);

		return true;
	}

_out:	if (!dontforwardconfupdates()) forward_request(c);

	if (!strcmp(b64conf, "START")) {
		run_script("confupdate-before");
		return true;
	}

	else if (!strcmp(b64conf, "END")) {
		run_script("confupdate-after");

		schedulereload();

		return true;
	}

	xasprintf(&fname, "%s/tinc.conf", confbase);
	fp = fopen(fname, "w");
	if (!fp) {
		logger(LOG_ERR, "Could not update %s: %s", fname, strerror(errno));
		free(fname);
		return true;
	}

	/* Save variables which are sensitive */
	for (x = 0; confvarstopreserve[x]; x++) {
		if(get_config_string(lookup_config(config_tree,
			confvarstopreserve[x]), &tname)) {
				fprintf(fp, "%s = %s\n", confvarstopreserve[x], tname);
			free(tname);
		}
	}

	/* Decode and append our template */
	base64_decode(b64conf, rawconf, sizeof(rawconf)-1);

	fwrite(rawconf, slen, 1, fp);
	fclose(fp);

	free(fname);
	return true;
}
