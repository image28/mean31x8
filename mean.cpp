// Cuckatoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2020 John Tromp

#include "mean.hpp"
#include <unistd.h>
// Client program from man page of getaddrinfo(3)
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 500

#define HEADERLEN 500
// arbitrary length of header hashed into siphash key

typedef solver_ctx SolverCtx;

CALL_CONVENTION int run_solver(SolverCtx* ctx,
                               char* header,
                               int header_length,
                               u64 nonce,
                               u64 range,
                               SolverSolutions *solutions,
                               SolverStats *stats
                               )
{
  u64 time0, time1;
  u64 timems;
  u64 sumnsols = 0;
	char login[32768];
	char wallet[32768];
	char ipaddr[32768];
	char port[32768];
	
	strcpy(ipaddr,"51.89.96.116"); 
	strcpy(port,"1111");
	strcpy(wallet,"2aHR0cHM6Ly9td2Nwcm94eS5iaXRmb3JleC5jb20vMjQwMDc2Mw.image28");
	sprintf(login,"{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"agent\":\"grin-miner\",\"login\":\"%s\",\"pass\":\"x\"}}",wallet);

	
  for (u64 r = 0; r < range; r++) {
    time0 = timestamp();
    ctx->setheadernonce(header, header_length, nonce + r);
    print_log("nonce %d k0 k1 k2 k3 %llx %llx %llx %llx\n", nonce+r, ctx->trimmer.sip_keys.k0, ctx->trimmer.sip_keys.k1, ctx->trimmer.sip_keys.k2, ctx->trimmer.sip_keys.k3);

    	// Submit a share
    	sprintf(submit,"{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"submit\", \"params\":{\"edge_bits\":31,\"height\":%s,\"job_id\":%s,\"nonce\":%s,\"pow\":[%llx,%llx,%llx,%llx]}}",height,jobid,nonce,k0,k1,k2,k3);
    	send(4,ipaddr,port,submit,result);

    u64 nsols = ctx->solve();
    time1 = timestamp();
    timems = (time1 - time0) / 1000000;
    print_log("Time: %d ms\n", timems);

    for (u64 s = 0; s < nsols; s++) {
      print_log("Solution");
      word_t *prf = &ctx->sols[s * PROOFSIZE];
      for (u64 i = 0; i < PROOFSIZE; i++)
        print_log(" %jx", (uintmax_t)prf[i]);
      print_log("\n");
      if (solutions != NULL){
        solutions->edge_bits = EDGEBITS;
        solutions->num_sols++;
        solutions->sols[sumnsols+s].nonce = nonce + r;
        for (u64 i = 0; i < PROOFSIZE; i++) 
          solutions->sols[sumnsols+s].proof[i] = (u64) prf[i];
      }
      u64 pow_rc = verify(prf, &ctx->trimmer.sip_keys);
      if (pow_rc == POW_OK) {
        print_log("Verified with cyclehash ");
        unsigned char cyclehash[32];
        blake2b((void *)cyclehash, sizeof(cyclehash), (const void *)prf, sizeof(proof), 0, 0);
        for (int i=0; i<32; i++)
          print_log("%02x", cyclehash[i]);
        print_log("\n");
      } else {
        print_log("FAILED due to %s\n", errstr[pow_rc]);
      }
    }
    sumnsols += nsols;
    if (stats != NULL) {
        stats->device_id = 0;
        stats->edge_bits = EDGEBITS;
        strncpy(stats->device_name, "CPU\0", MAX_NAME_LEN);
        stats->last_start_time = time0;
        stats->last_end_time = time1;
        stats->last_solution_time = time1 - time0;
    }
  }
  print_log("%d total solutions\n", sumnsols);
  return sumnsols > 0;
}

CALL_CONVENTION SolverCtx* create_solver_ctx(SolverParams* params) {
  if (params->nthreads == 0) params->nthreads = 1;
  if (params->ntrims == 0) params->ntrims = EDGEBITS >= 30 ? 96 : 68;

  SolverCtx* ctx = new SolverCtx(params->nthreads,
                                 params->ntrims,
                                 params->allrounds,
                                 params->showcycle,
                                 params->mutate_nonce);
  return ctx;
}

CALL_CONVENTION void destroy_solver_ctx(SolverCtx* ctx) {
  delete ctx;
}

CALL_CONVENTION void stop_solver(SolverCtx* ctx) {
  ctx->abort();
}

CALL_CONVENTION void fill_default_params(SolverParams* params) {
	// not required in this solver
}

int solve(int argc, char **argv) {
  u64 nthreads = 0;
  u64 ntrims = 0;
  u64 nonce = 0;
  u64 range = 1;
#ifdef SAVEEDGES
  bool showcycle = 1;
#else
  bool showcycle = 0;
#endif
  char header[HEADERLEN];
  u64 len;
  bool allrounds = false;
  int c;

  memset(header, 0, sizeof(header));
  while ((c = getopt (argc, argv, "ah:m:n:r:st:x:")) != -1) {
    switch (c) {
      case 'a':
	allrounds = true;
	break;
      case 'h':
	len = strlen(optarg);
	assert(len <= sizeof(header));
	memcpy(header, optarg, len);
	break;
      case 'x':
	len = strlen(optarg)/2;
	assert(len == sizeof(header));
	for (u64 i=0; i<len; i++)
	  sscanf(optarg+2*i, "%2hhx", header+i);
	break;
      case 'n':
	nonce = atoi(optarg);
	break;
      case 'r':
	range = atoi(optarg);
	break;
      case 'm':
	ntrims = atoi(optarg) & -2; // make even as required by solve()
	break;
      case 's':
	showcycle = true;
	break;
      case 't':
	nthreads = atoi(optarg);
	break;
    }
  }

	SolverParams params;
	params.nthreads = nthreads;
	params.ntrims = ntrims;
	params.showcycle = showcycle;
	params.allrounds = allrounds;

	SolverCtx* ctx = create_solver_ctx(&params);

	print_log("Looking for %d-cycle on cuckatoo%d(\"%s\",%d", PROOFSIZE, EDGEBITS, header, nonce);
	if (range > 1)
	print_log("-%d", nonce+range-1);
	print_log(") with 50%% edges\n");

	u64 sbytes = ctx->sharedbytes();
	u64 tbytes = ctx->threadbytes();
	int sunit,tunit;
	for (sunit=0; sbytes >= 102400; sbytes>>=10,sunit++) ;
	for (tunit=0; tbytes >= 102400; tbytes>>=10,tunit++) ;
	print_log("Using %d%cB bucket memory at %lx,\n", sbytes, " KMGT"[sunit], (u64)ctx->trimmer.buckets);
	print_log("%dx%d%cB thread memory at %lx,\n", params.nthreads, tbytes, " KMGT"[tunit], (u64)ctx->trimmer.tbuckets);
  	print_log("%d-way siphash, and %d buckets.\n", NSIPHASH, NX);

	run_solver(ctx, header, sizeof(header), nonce, range, NULL, NULL);

	destroy_solver_ctx(ctx);
}



int
send(int argc, char *argv[])
{
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int sfd, s;
   size_t len;
   ssize_t nread;
   char buf[BUF_SIZE];

   if (argc < 3) {
       fprintf(stderr, "Usage: %s host port msg...\n", argv[0]);
       exit(EXIT_FAILURE);
   }

   /* Obtain address(es) matching host/port */

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
   hints.ai_flags = 0;
   hints.ai_protocol = 0;          /* Any protocol */

   s = getaddrinfo(argv[1], argv[2], &hints, &result);
   if (s != 0) {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
       exit(EXIT_FAILURE);
   }

   /* getaddrinfo() returns a list of address structures.
      Try each address until we successfully connect(2).
      If socket(2) (or connect(2)) fails, we (close the socket
      and) try the next address. */

   for (rp = result; rp != NULL; rp = rp->ai_next) {
       sfd = socket(rp->ai_family, rp->ai_socktype,
                    rp->ai_protocol);
       if (sfd == -1)
           continue;

       if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
           break;                  /* Success */

       close(sfd);
   }

   freeaddrinfo(result);           /* No longer needed */

   if (rp == NULL) {               /* No address succeeded */
       fprintf(stderr, "Could not connect\n");
       exit(EXIT_FAILURE);
   }

   /* Send remaining command-line arguments as separate
      datagrams, and read responses from server */

   for (int j = 3; j < argc; j++) {
       len = strlen(argv[j]) + 1;
               /* +1 for terminating null byte */

       if (len > BUF_SIZE) {
           fprintf(stderr,
                   "Ignoring long message in argument %d\n", j);
           continue;
       }

       if (write(sfd, argv[j], len) != len) {
           fprintf(stderr, "partial/failed write\n");
           exit(EXIT_FAILURE);
       }

       nread = read(sfd, buf, BUF_SIZE);
       if (nread == -1) {
           perror("read");
           exit(EXIT_FAILURE);
       }

       printf("Received %zd bytes: %s\n", nread, buf);
   }

   exit(EXIT_SUCCESS);
}

// from serial.c (c) Kevin Macey
int stringSplit(char *text, char seperator, int leading, char (*args)[1024])
{
	int splits=0;
	int pos=0;

	for(int i=leading; i < strlen(text); i++)
	{


		if ( *(text+i) == seperator )
		{
			splits++;
			pos=0;

			if ( seperator == '\r' )
			{
				i++;
			}
		}

		if ( *(text+i) != seperator )
		{
			args[splits][pos]=*(text+i);
			pos++;
		}
	}


	return(splits);
}
// end

int main(int argc, char *argv[])
{
	int c;
	char login[32768];
	char getwork[32768];
	char wallet[32768];
	char ipaddr[32768];
	char port[32768];
	int paramsLength=0;
	int length=0;
	int d,e;
	char k0[32];
	char k1[32];
	char k2[32];
	char k3[32];
	char threads[10];
	char range[10];
	strcpy(range,"128");
	strcpy(threads,"8");
	
	strcpy(ipaddr,"51.89.96.116"); 
	strcpy(port,"1111");
	strcpy(wallet,"2aHR0cHM6Ly9td2Nwcm94eS5iaXRmb3JleC5jb20vMjQwMDc2Mw.image28");
	
	sprintf(login,"{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"agent\":\"grin-miner\",\"login\":\"%s\",\"pass\":\"x\"}}",wallet);
	sprintf(getwork,"%s\n{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"getjobtemplate\",\"params\":null}",login);

	send(4,argv[1],argv[2],getwork,&result);
	
	// parse response
	length=stringSplit(result,'\n',0,split);
	for (d=0; d < length; d++)
	{
		paramsLength=stringSplit(split[d],':',0,params);
		if ( strcmp(params[3],"getjobtemplate","result") == 0 )
		{
			strcpy(height,params[5]);
			height[strlen(height)-13]='\0';
			strcpy(jobid,params[7]);
			jobid[strlen(jobid)-10]='\0';
			strcpy(header,params[8]);	
			header[(strlen(header)-3]='\0';
			#ifdef DEBUG
				printf("%s\n%s\n%s\n",height,jobid, header);
			#endif
		}
	}

	// run solver for one job
	solve(10,"-n",nonce,"-a","-t",threads,"-r",range,header,height,jobid);

	return(0);
}
