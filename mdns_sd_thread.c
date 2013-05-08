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
 * mDNS-SD responder thread
 *
 * This thread listen for mDNS-SD packets, and resolves them using the mDNS-SD
 * library.
 * 
 * When a new packet arrives, the callbacks try to claim the buffer and if that
 * is not possible the packet is discarded. Otherwise the packet is copied into
 * the buffer (which is of size one MTU). When the packet is copied onto the
 * buffer the callback signals that there is new data to the mDNS thread and
 * then releases the buffer.
 * 
 * @author		EMO
 * (@version	0.1)
 * (@date		2011-08-02)
 */

//////////////////////////////////////////////////////////////////////
/// @name Includes
//@{

#include "SafeRTOS/SafeRTOS_API.h"
#include "thread_opts.h"
#include "utils/uartstdio.h"
#include "utils/lwiplib.h"

#include "lwip/udp.h"

#include "snap_utils.h"
#include "mdns_sd.h"

//#include <stdlib.h>
//#include <time.h>

//@} End of Includes


//////////////////////////////////////////////////////////////////////
/// @name Defines
//@{

#define MDNS_IP 	"224.0.0.251"
#define MDNS_PORT	5353

//@} End of Defines


//////////////////////////////////////////////////////////////////////
/// @name Typedefs
//@{

typedef struct {
  xQueueHandle queue;
  signed char buffer[sizeof(void *) + portQUEUE_OVERHEAD_BYTES];
} queue_t;

//@} End of Typedefs


//////////////////////////////////////////////////////////////////////
/// @name Data
//@{


static queue_t mdns_comq;	// signal new packet
static queue_t buf_sem;		// buffer semaphore

// mDNS-SD responder stack
static signed portCHAR mdns_stack[STACK_SIZE_MDNS];

// buffer for mDNS-SD packets
static char buffer[1500]; // one MTU in size
volatile static unsigned int buffer_su = 0; // Buffer size used 

//@} End of Data


//////////////////////////////////////////////////////////////////////
/// @name Private Methods
//@{

/**
 * Callback incoming mDNS-SD packets.
 * 
 * Copies incoming mDNS-SD packet to the buffer and signals the mdns thread.
 */
static void mdns_packet_rcvd(	void *arg, struct udp_pcb *upcb, struct pbuf *p,
                       			struct ip_addr *addr, u16_t port)
{
	portBASE_TYPE  res;
	void          *msg;
	unsigned int   i;
	
	/* Try to take buffer semaphore */
	res = xQueueSend(buf_sem.queue, &msg,0);
	if ( res != pdPASS ) {
		UARTprintf("res = %d\n", res);
		snap_diag("dropping mDNS packet");
		return;
	}
	
	/* copy data into buffer */
	buffer_su = 0;
	while (1) {
		for (i = 0; i < p->len; i++ ) {
			buffer[buffer_su++] = ((const char*)p->payload)[i];
		}
		if ( p->tot_len != p->len ) {
			p = p->next;
		}
		else {
			break;
		}
	} 
	
	/* Signal new data in buffer */
	res = xQueueSend(mdns_comq.queue,(void*)&msg,0);
	if ( res != pdPASS ) {
		UARTprintf("res = %d\n", res);
		snap_warn("not good");
	}
	
	/* Release buffer */
	xQueueReceive(buf_sem.queue, &msg, 0);
}

/**
 * When IP address is aquired, start by announcing services (i.e. that this
 * is a SNAP). The announcement is done in yet another short lived thread that
 * only exists during startup.
 */
static void mdns_thread(void* parameter)
{
	(void)parameter;
	
	int i;
	struct pbuf    *pb;
	struct udp_pcb *mdns_pcb;
	struct ip_addr  mcast;
	err_t			err;
	void           *msg;
	portBASE_TYPE   qres;
	
	snap_waitforip();
	
	/* set up raw UDP connection */
	mdns_pcb = udp_new();
	if ( !mdns_pcb ) {
		snap_fatal("failed to create mdns pcb");
	}
	err = udp_bind(mdns_pcb, IP_ADDR_ANY,MDNS_PORT);
	if ( err != ERR_OK ) {
		snap_fatal("failed to bind mdns port");
	}
	if ( err != ERR_OK ) {
		snap_fatal("failed to connect to mdns port");
	}
	mcast.addr = inet_addr(MDNS_IP);
	err = igmp_joingroup(IP_ADDR_ANY, &mcast);
	
	udp_recv(mdns_pcb, mdns_packet_rcvd, NULL);
	
	/* wait a random time */
// TODO srand( time(NULL) );
// TODO i = rand() % 250;
	i = 137;
	
	xTaskDelay(i);
	
	/* Probe three times */
	for ( i = 0; i < 3; i++ ) {
		pb = mdns_startup_probe();
		
		err = udp_sendto(mdns_pcb, pb, &mcast, MDNS_PORT);
		if ( err != ERR_OK ) {
			snap_fatal("failed to send packet");
		}
		qres = xQueueReceive(mdns_comq.queue, &msg, 250);
		switch (qres) {
			case pdPASS:
				/* got something from queue, not good */
				snap_warn("got message from queue during probing");
				
				/* Take semaphore */
				while (xQueueSend(buf_sem.queue, &msg, portMAX_DELAY) != pdPASS);
				
				// TODO process data in buffer
				
				/* Give sempahore */
				xQueueReceive(buf_sem.queue, &msg, 0);
				break; 
			case errQUEUE_EMPTY:
				/* queue was empty, better :) */
				snap_diag("no conflict detected");
				break;
			default:
				snap_fatal("Unexpected return value");
				break;
		} 
	}
	
	// TODO announce services
	
	while(1) {
		// TODO handle announcement
		/* wait for new packet signal */
		while ( xQueueReceive(mdns_comq.queue, &msg, portMAX_DELAY) != pdPASS );
		
		/* Take buffer semaphore */
		while (xQueueSend(buf_sem.queue, &msg, portMAX_DELAY) != pdPASS);
		
		snap_diag("parsing mDNS-SD packet");
		pb = mdns_parse(buffer, buffer_su);
		if ( pb ) {
			err = udp_sendto(mdns_pcb, pb, &mcast, MDNS_PORT);
			if ( err != ERR_OK ) {
				snap_warn("failed to send mDNS response");
			}
		}
		
		/* Give buffer semaphore */
		xQueueReceive(buf_sem.queue, &msg, 0);
	} 
}

//@} End of Private Methods


//////////////////////////////////////////////////////////////////////
/// @name Public Methods
//@{

int mDNS_thread_init()
{
	portBASE_TYPE res;
	
	res = xQueueCreate( mdns_comq.buffer, sizeof(mdns_comq.buffer), 1,
						sizeof(void*), &mdns_comq.queue );
	if( res != pdPASS ) {
		snap_fatal("Failed to create queue");
	}
	
	res = xQueueCreate( buf_sem.buffer, sizeof(mdns_comq.buffer), 1,
						sizeof(void*), &buf_sem.queue );
	if( res != pdPASS ) {
		snap_fatal("Failed to create queue");
	}
	
	res = xTaskCreate(	mdns_thread, (signed char*)"mDNS-SD", mdns_stack,
						sizeof(mdns_stack), NULL, PRIORITY_MDNS, NULL);
	if (  res != pdPASS ) {
		return 1;
	}
	return 0;
}

//@} End of Public Methods
