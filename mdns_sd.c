/*****************************************************************************
 *                                                                           *
 *                         ,7tbEW8Ez2Y                                       *
 *                   vA##$67.                                                *
 *             cMMMMMM$v.                                                    *
 *         ,MMMMMM:       MMMMMMM.                                           *
 *       MMMMMW         .MMMMMMMM                                            *
 *     MMMMMc           MMMM      tMMM    vMM#  cMMMMMi   7MM,@MMMM:         * 
 *    MMMMM             @MMMM@.   .MMMc   MMM, MMMMMMMMM  MMMMMMMMMMM        * 
 *   MMMMMM              WMMMMMMM  9MMM  MMMM MMMM   MMMz MMMM   cMMM.       * 
 *  MMMMMMM                 XMMMMM  MMMW MMM  MMMMMMMMMMM MMMM    MMMI       * 
 *  MMMMMMMM                  ;MMM   MMMMMM.  MMMM     .  MMMM    MMM.       * 
 *  MMMMMMMMM;          oMMMMMMMMM   #MMMMM    MMMMMMMMM  MMMMMMMMMMM  MMM   *
 *   @MMMMMMMMMM        :MMMMMMMc     MMMM      EMMMMMMM  MMMMMMMMM6   MMM   *
 *    #MMMMMMMMMMMMZ.                                     MMMM               *
 *      MMMMMMMMMMMMMMMM@o.                        DESIGN MMMM CENTER        *
 *        WMMMMMMMMMMMMMMMMMMMMMMMMM@WQAo1zX              MMMM               *
 *           IMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMC                              *
 *               cMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM;                           *
 *                      .CbMMMMMMMMMMMMMMMMMMMMMMMMM:                        *
 *                                                                           *
 *****************************************************************************/

/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <emo@svep.se> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return
 * - Emil Ohlsson
 * ----------------------------------------------------------------------------
 */

/**
 * A light weight mDNS-SD responder
 *
 * This is a light weight implementation of mDNS-SD to be used in SNAP.
 * 
 * @author		EMO
 * (@version	0.1)
 * (@date		2011-08-02)
 */

//////////////////////////////////////////////////////////////////////
/// @name Includes
//@{

#include "bukkit_o_knowledge.h"
#include "snap_conf.h"
#include "utils/lwiplib.h"
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

//@} End of Includes


//////////////////////////////////////////////////////////////////////
/// @name Defines
//@{

/* Returns 1 if package is response */
#define dns_qr(x) ((x)->flags & 0x0080)

//@} End of Defines


//////////////////////////////////////////////////////////////////////
/// @name Typedefs
//@{

typedef struct dns_h_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;	// question count
	uint16_t ancount;	// answer count
	uint16_t nscount;	// authority records
	uint16_t arcount;	// resource records
} __attribute__((__packed__)) dns_h_t;

typedef struct dns_q_t {
	uint16_t qtype;
	uint16_t qclass;
} __attribute__((__packed__)) dns_q_t;

typedef struct dns_r_t {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
} __attribute__((__packed__)) dns_r_t;

typedef struct {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
} __attribute__((__packed__)) dns_srv_t;

typedef enum { false, true } bool;

//@} End of Typedefs


//////////////////////////////////////////////////////////////////////
/// @name Data
//@{

static char name[] = "\x004SNAP\x005local";

//@} End of Data


//////////////////////////////////////////////////////////////////////
/// @name Private Methods
//@{

/**
 * write data to a pbuf
 *
 * @param	pb		Packet buffer to write to. Used as a stream.
 * @param	offst	offset in current packet buffer.
 * @param	d		pointer to data
 * @param	len		length of data to write
 * @param	wlen	Total amount of written data
 */
static int write_to_pbuf( struct pbuf **pb, unsigned int *offst, const char* d,
                          unsigned int len, unsigned int *wlen)
{
	unsigned int  i = 0;
	char         *dp = (*pb)->payload;
	
	for ( i = 0; i < len; ) {
		// TODO this somehow feels like a bug
		for (; i < (*pb)->len && i < len; (*offst)++, i++ ) {
			dp[*offst] = d[i];
			(*wlen)++;
		}
		
		if ( len - i == 0 ) {
			return 0;
		}
		if ( (*pb)->next == NULL ) {
			return 1;
		}
		*pb = (*pb)->next;
		*offst = 0;
	}
	return 0;
}

/**
 * Write a name to pbuf, such as "._snap._tcp"
 *
 * Not very fast, but simple. Does not have support for compression.
 */
static void write_name_to_pbuf( struct pbuf **pb, unsigned int *offst,
							   const char *name, unsigned int *wlen )
{
	char 		  lbuffer[64];		/* Label buffer */
	unsigned int  i = 0;
	uint8_t		  ll;

	while ( name[i] == '.') {
		ll = 1;
		/* calculate length of label */
		while ( name[i + ll] != '.' && name[i+ll] != '\0' ) ll++;
		name ++;
		write_to_pbuf(pb,offst,&ll,1,wlen);
		write_to_pbud(pb,offst,name,ll,wlen);
	}
	ll = 0;
	write_to_pbuf(pb,offst,&ll,1,wlen);
}

/** 
 * Try to accept a DNS formated entry.
 *
 * Check if an entry matches a keyword. Have support for simple formatted
 * strings.
 *
 * Usage:
 * 		mdns_accept(hp,&sp,ep,"._snap._tcp.local");
 * 		or
 * 		mdns_accept(hp,&sp,ep,".$.$.$", "_snap","_tcp", "local");
 * 
 * @param	hp  header pointer, used for decompressing
 * @param	sp  stream pointer
 * @param	ep  end pointer
 * @param	k   keyword to accept
 */
static bool mdns_accept( const char *hp, const char **sp,
                         const char *ep, const char *k, ...)
{
	const char   *p, *tp, *ump;	// pointer, temp pointer, unmodified pointer
	const char   *old_k;
	bool          compressed = false;
	bool          ext = false;
	int           i = 0;
	unsigned char len;
	u16_t         ofs;
	va_list		  vl;
	
	va_start(vl, k);

	ump = tp = p = *sp;
	while ( tp < ep ) {
		if ( *tp == 0 ) {
			/* end of text entry */
			if ( *k == 0 ) {
				/* keyword matched */
				if ( !compressed ) p++;
				*sp = p;
				va_end(vl);
				return true;
			}
			else {
				/* no match */
				*sp = ump;
				va_end(vl);
				return false;
			}
		}
		else if ( (*tp & 0xc0) == 0xc0 ) {
			/* Compressed label */
			ofs = htons( 0xff3f & *(uint16_t*)tp);
			if ( !compressed ) {
				p += 2;
			}
			compressed = true;
			
			tp = hp + ofs;
			if ( tp > ep ) {
				/* out of packet */
				*sp = ump;
				va_end(vl);
				return false;
			}
		}
		else {
			/* ordinary label */
			len = *tp++;
			if ( *k++ != '.' ) {
				/* mismatch */
				*sp = ump;
				va_end(vl);
				return false;
			}
			if ( *k == '$') {
				old_k = k;
				k = va_arg(vl, const char*);
				ext = true;
			}
			for ( i = 0; i < len; i++ ) {
				if ( *k != *tp ) {
					/* mismatch */
					*sp = ump;
					va_end(vl);
					return false;
				}
				if ( !compressed ) p++;
				k++;
				tp++;
			} 
			if ( ext ) {
				ext = false;
				k = old_k + 1;
			}
		}
	}
	va_end(vl);
	return false;	
}

/**
 * set pointer to first byte after label. Returns false if stream went outside
 * packet.
 */
static bool mdns_discard_label( const char **sp,	// Stream pointer
                                const char *ep )	// end pointer
{
	const char *p, *ump;
	
	ump = p = *sp;
	while ( p < ep ) {
		if ( *p == 0 ) {
			/* end of text entry */
			*sp = p + 1;
			return true;
		}
		else if ( (*p & 0xc0) == 0xc0 ) {
			/* Compressed label */
			*sp = p + 2;
			return true;
		}
		p = p + (unsigned char)*p;
	}
	*sp = ump;
	return false;
}

/**
 * Comments about DNS records
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |
 *    /                                               /
 *    /                      NAME                     /
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TYPE                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     CLASS                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TTL                      |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   RDLENGTH                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *    /                     RDATA                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

/**
 * Write an A record to packet
 */
static void mdns_a_record(struct pbuf **pb, unsigned int *o)
{
	// TODO
	write_name_to_pbuf(pb, offst,"._snap._tcp",wlen);
}

/**
 * Write an SRV record to packet
 */
static void mdns_srv_record()
{
	// TODO
}

/**
 * Write an PTR record to packet
 */
static void mdns_ptr_record()
{
	// TODO
}

/**
 * Write an TXT record to packet
 */
static void mdns_txt_record()
{
	// TODO
}

/**
 * Parses data stream at dp. writes any response to bp. If any data was written
 * 1 is returned. If response buffer is untouched 0 is returned.
 * offset is used to remember where in pbuf to write
 */
static unsigned int mdns_parse_query( const char *hp,		// Header pointer
									  const char **sp,		// stream pointer
									  const char *ep,		// end pointer
									  struct pbuf **pb,		// packet buffer
									  unsigned int *offset,	// packet buffer offset
									  unsigned int *wlen)	// written amount of bytes
{
	bool           res;
	const char    *name;
	const char	  *srv = "\x005_snap\x004_tcp\x005local";
	char           nbyte;
	dns_r_t        qr;
	dns_srv_t      sr;
	unsigned long  ip = lwIPLocalIPAddrGet();

	res = mdns_accept(hp,sp,ep,"._snap._tcp.local");
	if ( res ) {
		name = snap_take_get_name();
		nbyte = strlen(name);

		// Add PTR response
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);
		qr.type     = 0x0c00;		// Type PTR
		qr.class    = 0x0100;		// Class IN, cache flush
		qr.ttl      = 0x94110000;	// 1 hour 15 minutes
		qr.rdlength = htons( 1 + nbyte + strlen(srv) + 1 );
		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);

		// Add SRV response
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);

		qr.class = 0x0180;		// Class IN, cache flush
		qr.type = 0x2100;		// Type Service location
		qr.ttl = 0x78000000;	// About two minutes
		qr.rdlength = htons(sizeof(sr) + strlen(name)+1 + strlen("\x005local"));
		sr.port = htons(SNAP_UI_DEFAULT_PORT);
		sr.priority = 0;
		sr.weight = 0;

		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, (char*)&sr, sizeof(sr), wlen);
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, "\x005local", 7, wlen);

		*sp += sizeof(dns_q_t);

		snap_give_name();
		return 2;
	}
	res = mdns_accept(hp,sp,ep,".$.local", name = snap_take_get_name());
	if ( res ) {
		/* Add A response */
		nbyte = strlen(name);
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);

		nbyte = strlen("local");
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, "local\0", nbyte+1, wlen);

		qr.class = 0x0180;		// Class IN, cache flush
		qr.rdlength = 0x0400;	// Size of IP address
		qr.ttl = 0x78000000;	// about two minutes
		qr.type = 0x0100;		// Type A;
		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, (char*)&ip, 4, wlen);

		/* increase stream pointer */
		*sp += sizeof(dns_q_t);

		snap_give_name();
		return 1;
	}
	snap_give_name();
	res = mdns_accept(hp,sp,ep,"._services._dns-sd._udp.local");
	if ( res ) {
		// add response
		name = snap_take_get_name();
		nbyte = strlen(name);

		// Add PTR response
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);
		qr.type     = 0x0c00;		// Type PTR
		qr.class    = 0x0100;		// Class IN, cache flush
		qr.ttl      = 0x94110000;	// 1 hour 15 minutes
		qr.rdlength = htons( 1 + nbyte + strlen(srv) + 1 );
		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);

		// Add A response
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);

		nbyte = strlen("local");
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, "local\0", nbyte+1, wlen);

		qr.class = 0x0180;		// Class IN, cache flush
		qr.rdlength = 0x0400;	// Size of IP address
		qr.ttl = 0x78000000;	// about two minutes
		qr.type = 0x0100;		// Type A;
		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, (char*)&ip, 4, wlen);

		// Add SRV response
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, srv, strlen(srv)+1, wlen);

		qr.class = 0x0180;		// Class IN, cache flush
		qr.type = 0x2100;		// Type Service location
		qr.ttl = 0x78000000;	// About two minutes
		qr.rdlength = htons(sizeof(sr) + strlen(name)+1 + strlen("\x005local"));
		sr.port = htons(SNAP_UI_DEFAULT_PORT);
		sr.priority = 0;
		sr.weight = 0;

		write_to_pbuf(pb, offset, (char*)&qr, sizeof(qr), wlen);
		write_to_pbuf(pb, offset, (char*)&sr, sizeof(sr), wlen);
		write_to_pbuf(pb, offset, &nbyte, 1, wlen);
		write_to_pbuf(pb, offset, name, nbyte, wlen);
		write_to_pbuf(pb, offset, "\x005local", 7, wlen);

		*sp += sizeof(dns_q_t);

		snap_give_name();
		return 3;
	}
	mdns_discard_label(sp, ep);
	*sp += sizeof(dns_q_t);
	
	return 0;
}

/**
 * Parses data stream at dp. writes any response to bp. If any data was written
 * 1 is returned. If response buffer is untouched 0 is returned.
 * offset is used to remember where in pbuf to write */
static bool mdns_parse_resource( const char *sp, const char **dp,
								 const char *ep, struct pbuf **bp,
								 unsigned int *offset)
{
	return false;
}

//@} End of Private Methods


//////////////////////////////////////////////////////////////////////
/// @name Public Methods
//@{

/**
 * Parse an mDNS-SD packet
 *
 * Parses an mDNS-SD packet and creates a response.
 */
struct pbuf *mdns_parse(void* ptr, int nbytes)
{
	/* header pointers */
	dns_h_t      *dns_p = ptr;	/* header of incoming packet */
	dns_h_t      *hp;			/* header of outgoing packet */
	
	const char   *datap = (char*)ptr + sizeof(dns_h_t);
	const char   *endp = datap + nbytes;	/* end pointer */
	bool          response = false;			/* response constructed */
	struct pbuf  *pb;			/* packet buffer */
	struct pbuf  *tpb;			/* temporary packet buffer */
	unsigned int  offset = sizeof(dns_h_t);
	unsigned int  wlen = sizeof(dns_h_t);
	unsigned int  rec_w = 0; 	/* Records written */
	
	/* check content of packet */
	u16_t qdcount = htons(dns_p->qdcount);
	u16_t ancount = htons(dns_p->ancount);
	u16_t nscount = htons(dns_p->nscount);
	u16_t arcount = htons(dns_p->arcount);
	u16_t i;

    dns_p = ptr;
	tpb = pb = pbuf_alloc( PBUF_TRANSPORT, 1400, PBUF_RAM );
	hp = (dns_h_t*)pb->payload;
	
	hp->id = 0;
	hp->flags = 0x0084;		/* Response, authorative */
	hp->qdcount = 0;
	hp->ancount = 0;
	hp->nscount = 0;
	hp->arcount = 0;
	
	/* Process questions */
	for ( i = 0; i < qdcount; i++ ) {
		rec_w = mdns_parse_query(ptr, &datap, endp, &tpb, &offset, &wlen);
		if ( rec_w ) {
			hp->ancount = htons(htons(hp->ancount)+rec_w);
			response = true;
		}
	}
	
	/* Process answers */
	for ( i = 0; i < ancount; i++ ) {
		response |= mdns_parse_resource(ptr, &datap, endp, &tpb, &offset);
	}
	
	/* Process name authorative name servers */
	for ( i = 0; i < nscount; i++ ) {
		response |= mdns_parse_resource(ptr, &datap, endp, &tpb, &offset);
	}
	
	/* Process additional resources */
	for ( i = 0; i < arcount; i++ ) {
		response |= mdns_parse_resource(ptr, &datap, endp, &tpb, &offset);
	}
	
	if ( !response ) {
		pbuf_free( pb );
		return NULL;
	}
	pbuf_realloc(pb, wlen);
	
	return pb;
}

struct pbuf *mdns_startup_probe()
{
	unsigned int  i = 0;
	unsigned int  wlen = 0;
	struct pbuf  *pb;
	int           res;
	dns_h_t       header = {0,0,htons(1),0,0,0};
	dns_q_t       query;
	
	pb = pbuf_alloc( PBUF_TRANSPORT, 1400, PBUF_RAM );
	
	res = write_to_pbuf(&pb,&i, (char*)&header, sizeof(header), &wlen);
	if ( res ) {snap_fatal("Failed to create startup probe");}
	res = write_to_pbuf(&pb,&i, name, sizeof(name), &wlen);
	if ( res ) {snap_fatal("Failed to create startup probe");}
	
	query.qtype = htons(0x00ff);
	query.qclass = htons(0x0001);
	res = write_to_pbuf(&pb, &i,(char*)&query,sizeof(query),&wlen);
	
	pbuf_realloc(pb, wlen);
	
	return pb;
}

//@} End of Public Methods
