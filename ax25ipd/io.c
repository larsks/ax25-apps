/* io.c 		All base I/O routines live here
 *
 * Copyright 1991, Michael Westerhof, Sun Microsystems, Inc.
 * This software may be freely used, distributed, or modified, providing
 * this header is not removed.
 *
 * This is the only module that knows about base level UNIX/SunOS I/O
 * This is also the key dispatching module, so it knows about a lot more
 * than just I/O stuff.
 */
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <termio.h>
#include <time.h>
#include <unistd.h>

#include "ax25ipd.h"

static struct termio nterm;

int ttyfd = -1;
static int udpsock = -1;
static int sock = -1;
static struct sockaddr_in udpbind;
static struct sockaddr_in to;
static struct sockaddr_in from;
static socklen_t fromlen;

static time_t last_bc_time;

int ttyfd_bpq = 0;

/*
 * I/O modes for the io_error routine
 */
#define READ_MSG 0x00
#define SEND_MSG 0x01

#define IP_MODE 0x10
#define UDP_MODE 0x20
#define TTY_MODE 0x30

#ifndef FNDELAY
#define FNDELAY O_NDELAY
#endif

/*
 * process an I/O error; return true if a retry is needed
 *
 * oops		- the error flag; < 0 indicates a problem
 * buf		- the data in question
 * bufsize	- the size of the data buffer
 * dir		- the direction; input or output
 * mode		- the fd on which we got the error
 * where	- line in the code where this function was called
 */
static int io_error(int oops, unsigned char *buf, int bufsize, int dir,
                    int mode, int where) {

  /* if (oops >= 0)
          return 0; */	/* do we have an error ? */
  /* dl9sau: nobody has set fd's to O_NONBLOCK.
   * thus EAGAIN (below) or EWOULDBLOCK are never be set.
   * Has someone removed this behaviour previously?
   * Anyway, in the current implementation, with blocking
   * read/writes, a read or write of 0 bytes means EOF,
   * for e.g. if the attached tty is closed.
   * We have to exit then. We've currentlsy no mechanism
   * for regulary reconnects.
   */
  if (oops > 0)
    return 0; /* do we have an error ? */

  if (oops == 0) {
    if (dir == READ_MSG &&
        oops != TTY_MODE /* && != TCP_MODE, if we'd implement this */)
      return 0;
    fprintf(stderr,
            "Close event on mode 0x%2.2x (during %s). LINE %d. Terminating "
            "normaly.\n",
            mode, (dir == READ_MSG ? "READ" : "WRITE"), where);
    exit(1);
  }

#ifdef EAGAIN
  if (errno == EAGAIN) {
#ifdef notdef
    /* select() said that data is available, but recvfrom sais
     * EAGAIN - i really do not know what's the sense in this.. */
    if (dir == READ_MSG &&
        oops != TTY_MODE /* && != TCP_MODE, if we'd implement this */)
      return 0;
    perror("System 5 I/O error!");
    fprintf(stderr, "A System 5 style I/O error was detected.  This rogram "
                    "requires BSD 4.2\n");
    fprintf(
        stderr,
        "behaviour.  This is probably a result of compile-time environment.\n");
    fprintf(stderr, "Mode 0x%2.2x, LINE: %d. During %s\n", mode, where,
            (dir == READ_MSG ? "READ" : "WRITE"));
    exit(3);
#else
    int ret = 0;
    if (dir == READ_MSG) {
      LOGL4("read / recv returned -1 EAGAIN\n");
      ret = 0;
    } else if (dir == SEND_MSG) {
      LOGL4("write / send returned -1 EAGAIN, sleeping and retrying!\n");
      usleep(100000);
      ret = 1;
    }
    return ret;
#endif
  }
#endif

  if (dir == READ_MSG) {
    if (errno == EINTR)
      return 0; /* never retry read */
    if (errno == EWOULDBLOCK) {
      LOGL4("READ would block (?!), sleeping and retrying!\n");
      usleep(100000); /* sleep a bit */
      return 1;       /* and retry */
    }
    if (mode == IP_MODE) {
      perror("reading from raw ip socket");
      exit(2);
    } else if (mode == UDP_MODE) {
      perror("reading from udp socket");
      exit(2);
    } else if (mode == TTY_MODE) {
      perror("reading from tty device");
      exit(2);
    } else {
      perror("reading from unknown I/O");
      exit(2);
    }
  } else if (dir == SEND_MSG) {
    if (errno == EINTR)
      return 1; /* always retry on writes */
    if (mode == IP_MODE) {
      if (errno == EMSGSIZE) { /* msg too big, drop it */
        perror("message dropped on raw ip socket");
        fprintf(stderr, "message was %d bytes long.\n", bufsize);
        return 0;
      }
      if (errno == ENETDOWN || errno == ENETRESET || errno == ENETUNREACH ||
          errno == EHOSTDOWN || errno == EHOSTUNREACH || errno == ENONET ||
          errno == EPERM) {
        /* host closed his axip receiver or dropped the line */
        perror("error after sending on to axip partner. ignoring.");
        LOGL4("error after sending on to axip partner: %s; ignoring!\n",
              strerror(errno));

        return 0;
      }
      if (errno == ENOBUFS) { /* congestion; sleep + retry */
        LOGL4("send congestion on raw ip, sleeping and retrying!\n");
        usleep(100000);
        return 1;
      }
      if (errno == EWOULDBLOCK) {
        LOGL4("send on raw ip would block, sleeping and retrying!\n");
        usleep(100000); /* sleep a bit */
        return 1;       /* and retry */
      }
      perror("writing to raw ip socket");
      exit(2);
    } else if (mode == UDP_MODE) {
      if (errno == EMSGSIZE) { /* msg too big, drop it */
        perror("message dropped on udp socket");
        fprintf(stderr, "message was %d bytes long.\n", bufsize);
        return 0;
      }
      if (errno == ENETDOWN || errno == ENETRESET || errno == ENETUNREACH ||
          errno == EHOSTDOWN || errno == EHOSTUNREACH || errno == ENONET ||
          errno == EPERM) {
        /* host closed his axudp receiver or dropped the line */
        perror("error after sending to axudp partner. ignoring.");
        LOGL4("error after sending to axudp partner: %s; ignoring!\n",
              strerror(errno));

        return 0;
      }
      if (errno == ENOBUFS) { /* congestion; sleep + retry */
        LOGL4("send congestion on udp, sleeping and retrying!\n");
        usleep(100000);
        return 1;
      }
      if (errno == EWOULDBLOCK) {
        LOGL4("send on udp would block, sleeping and retrying!\n");
        usleep(100000); /* sleep a bit */
        return 1;       /* and retry */
      }
      perror("writing to udp socket");
      exit(2);
    } else if (mode == TTY_MODE) {
      if (errno == EWOULDBLOCK) {
        LOGL4("write to tty would block, sleeping and retrying!\n");
        usleep(100000); /* sleep a bit */
        return 1;       /* and retry */
      }
      perror("writing to tty device");
      exit(2);
    } else {
      perror("writing to unknown I/O");
      exit(2);
    }
  } else {
    perror("Unknown direction and I/O");
    exit(2);
  }
  return 0;
}

/*
 * Initialize the io variables
 */

void io_init(void) {

  /*
   * Close the file descriptors if they are open.  The idea is that we
   * will be able to support a re-initialization if sent a SIGHUP.
   */

  if (ttyfd >= 0) {
    close(ttyfd);
    ttyfd = -1;
  }

  if (sock >= 0) {
    close(sock);
    sock = -1;
  }

  if (udpsock >= 0) {
    close(udpsock);
    udpsock = -1;
  }

  /*
   * The memset is not strictly required - it simply zeros out the
   * address structure.  Since both to and from are static, they are
   * already clear.
   */
  memset(&to, 0, sizeof(struct sockaddr));
  to.sin_family = AF_INET;

  memset(&from, 0, sizeof(struct sockaddr));
  from.sin_family = AF_INET;

  memset(&udpbind, 0, sizeof(struct sockaddr));
  udpbind.sin_family = AF_INET;
}

/*
 * Create a symbolic link at link_path pointing to target_path. If link_path
 * exists, remove it if it is a symbolic link before re-creating it.
 */

int create_safe_symlink(char *target_path, char *link_path) {
  struct stat statbuf_link;

  if (lstat(link_path, &statbuf_link) == 0) {
    if (S_ISLNK(statbuf_link.st_mode)) {
      if (unlink(link_path) != 0) {
        return -1;
      }
    } else {
      errno = EEXIST;
      return -1;
    }
  }

  if (symlink(target_path, link_path) != 0) {
    return -1;
  }

  return 0;
}

/*
 * open and initialize the IO interfaces
 */

void io_open(void) {
  int baudrate;
  int i_am_unix98_pty_master = 0; /* unix98 ptmx support */
  char *namepts = NULL;           /* name of the unix98 pts slave, which
                                   * the client has to use */

  if (ip_mode) {
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_AX25);
    if (sock < 0) {
      perror("opening raw socket");
      exit(1);
    }
    if (fcntl(sock, F_SETFL, FNDELAY) < 0) {
      perror("setting non-blocking I/O on raw socket");
      exit(1);
    }
  }

  if (udp_mode) {
    udpsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpsock < 0) {
      perror("opening udp socket");
      exit(1);
    }
    if (fcntl(udpsock, F_SETFL, FNDELAY) < 0) {
      perror("setting non-blocking I/O on UDP socket");
      exit(1);
    }
    /*
     * Ok, the udp socket is open.  Now express our interest in receiving
     * data destined for a particular socket.
     */
    udpbind.sin_addr.s_addr = INADDR_ANY;
    udpbind.sin_port = my_udp;
    if (bind(udpsock, (struct sockaddr *)&udpbind, sizeof udpbind) < 0) {
      perror("binding udp socket");
      exit(1);
    }
  }

  if (!strcmp("/dev/ptmx", ttydevice))
    i_am_unix98_pty_master = 1;

  ttyfd = ((ttyfd_bpq = (strchr(ttydevice, '/') ? 0 : 1))
               ? open_ethertap(ttydevice)
               : open(ttydevice, O_RDWR, 0));
  if (ttyfd < 0) {
    perror("opening tty device");
    exit(1);
  }
  if (fcntl(ttyfd, F_SETFL, FNDELAY) < 0) {
    perror("setting non-blocking I/O on tty device");
    exit(1);
  }

  if (i_am_unix98_pty_master) {
    /* get name of pts-device */
    namepts = ptsname(ttyfd);
    if (namepts == NULL) {
      perror("Cannot get name of pts-device.");
      exit(1);
    }
    /* unlock pts-device */
    if (unlockpt(ttyfd) == -1) {
      perror("Cannot unlock pts-device.");
      exit(1);
    }
    if (ptysymlink[0] != '\0') {
      if (create_safe_symlink(namepts, ptysymlink) != 0) {
        perror("Cannot create symlink to pts-device");
        exit(1);
      }
    }
  }

  if (ttyfd_bpq) {
    set_bpq_dev_call_and_up(ttydevice);
    goto behind_normal_tty;
  }
  if (ioctl(ttyfd, TCGETA, &nterm) < 0) {
    perror("fetching tty device parameters");
    exit(1);
  }

  if (ttyspeed == 50)
    baudrate = B50;
  else if (ttyspeed == 50)
    baudrate = B50;
  else if (ttyspeed == 75)
    baudrate = B75;
  else if (ttyspeed == 110)
    baudrate = B110;
  else if (ttyspeed == 134)
    baudrate = B134;
  else if (ttyspeed == 150)
    baudrate = B150;
  else if (ttyspeed == 200)
    baudrate = B200;
  else if (ttyspeed == 300)
    baudrate = B300;
  else if (ttyspeed == 600)
    baudrate = B600;
  else if (ttyspeed == 1200)
    baudrate = B1200;
  else if (ttyspeed == 1800)
    baudrate = B1800;
  else if (ttyspeed == 2400)
    baudrate = B2400;
  else if (ttyspeed == 4800)
    baudrate = B4800;
  else if (ttyspeed == 9600)
    baudrate = B9600;
#ifdef B19200
  else if (ttyspeed == 19200)
    baudrate = B19200;
#else
#ifdef EXTA
  else if (ttyspeed == 19200)
    baudrate = EXTA;
#endif /* EXTA */
#endif /* B19200 */
#ifdef B38400
  else if (ttyspeed == 38400)
    baudrate = B38400;
#else
#ifdef EXTB
  else if (ttyspeed == 38400)
    baudrate = EXTB;
#endif /* EXTB */
#endif /* B38400 */
#ifdef B57600
  else if (ttyspeed == 57600)
    baudrate = B57600;
#endif        /* B57600  */
#ifdef B76800 /* SPARC-specific  */
  else if (ttyspeed == 76800)
    baudrate = B76800;
#endif /* B76800  */
#ifdef B115200
  else if (ttyspeed == 115200)
    baudrate = B115200;
#endif         /* B115200  */
#ifdef B153600 /* SPARC-specific  */
  else if (ttyspeed == 153600)
    baudrate = B153600;
#endif /* B153600  */
#ifdef B230400
  else if (ttyspeed == 230400)
    baudrate = B230400;
#endif         /* B230400  */
#ifdef B307200 /* SPARC-specific  */
  else if (ttyspeed == 307200)
    baudrate = B307200;
#endif /* B307200  */
#ifdef B460800
  else if (ttyspeed == 460800)
    baudrate = B460800;
#endif /* B460800  */
#ifdef B500000
  else if (ttyspeed == 500000)
    baudrate = B500000;
#endif /* B500000  */
#ifdef B576000
  else if (ttyspeed == 576000)
    baudrate = B576000;
#endif         /* B576000  */
#ifdef B614400 /* SPARC-specific  */
  else if (ttyspeed == 614400)
    baudrate = B614400;
#endif         /* B614400  */
#ifdef B921600 /* SPARC-specific  */
  else if (ttyspeed == 921600)
    baudrate = B921600;
#endif /* B921600  */
#ifdef B1000000
  else if (ttyspeed == 1000000)
    baudrate = B1000000;
#endif /* B1000000  */
#ifdef B1152000
  else if (ttyspeed == 1152000)
    baudrate = B1152000;
#endif /* B1152000  */
#ifdef B1500000
  else if (ttyspeed == 1500000)
    baudrate = B1500000;
#endif /* B1500000  */
#ifdef B2000000
  else if (ttyspeed == 2000000)
    baudrate = B2000000;
#endif /* B2000000  */
#ifdef B2500000
  else if (ttyspeed == 2500000)
    baudrate = B2500000;
#endif /* B2500000  */
#ifdef B3000000
  else if (ttyspeed == 3000000)
    baudrate = B3000000;
#endif /* B3000000  */
#ifdef B3500000
  else if (ttyspeed == 3500000)
    baudrate = B3500000;
#endif /* B3500000  */
#ifdef B4000000
  else if (ttyspeed == 4000000)
    baudrate = B4000000;
#endif /* B4000000  */
  else
    baudrate = B9600;

  nterm.c_iflag = 0;
  nterm.c_oflag = 0;
  nterm.c_cflag = baudrate | CS8 | CREAD | CLOCAL;
  nterm.c_lflag = 0;
  nterm.c_cc[VMIN] = 0;
  nterm.c_cc[VTIME] = 0;

  if (ioctl(ttyfd, TCSETA, &nterm) < 0) {
    perror("setting tty device parameters");
    exit(1);
  }

  if (digi)
    send_params();

  if (i_am_unix98_pty_master) {
    /* Users await the slave pty to be referenced in the last line */
    printf("Awaiting client connects on\n%s\n", namepts);
    syslog(LOG_INFO, "Bound to master pty /dev/ptmx with slave pty %s\n",
           namepts);
  }

behind_normal_tty:

  last_bc_time = 0; /* force immediate id */
}

/*
 * Start up and run the I/O mechanisms.
 *  run in a loop, using the select call to handle input.
 */

void io_start(void) {
  int n, nb, hdr_len;
  fd_set readfds;
  unsigned char buf[MAX_FRAME];
  struct timeval wait;
  struct iphdr *ipptr;
  time_t now;

  for (;;) {

    if ((bc_interval > 0) && digi) {
      now = time(NULL);
      if (last_bc_time + bc_interval < now) {
        last_bc_time = now;
        LOGL4("iostart: BEACON\n");
        do_beacon();
      }
    }

    wait.tv_sec = 10; /* lets us keep the beacon going */
    wait.tv_usec = 0;

    FD_ZERO(&readfds);

    FD_SET(ttyfd, &readfds);

    if (ip_mode) {
      FD_SET(sock, &readfds);
    }

    if (udp_mode) {
      FD_SET(udpsock, &readfds);
    }

    nb = select(FD_SETSIZE, &readfds, (fd_set *)0, (fd_set *)0, &wait);

    if (nb < 0) {
      if (errno == EINTR)
        continue; /* Ignore */
      perror("select");
      exit(1);
    }

    if (nb == 0) {
      fflush(stdout);
      fflush(stderr);
      /* just so we go back to the top of the loop! */
      continue;
    }

    if (FD_ISSET(ttyfd, &readfds)) {
      do {
        n = read(ttyfd, buf, MAX_FRAME);
      } while (io_error(n, buf, n, READ_MSG, TTY_MODE, __LINE__));
      LOGL4("ttydata l=%d\n", n);
      if (n > 0) {
        if (!ttyfd_bpq) {
          assemble_kiss(buf, n);
        } else {
          /* no crc but MAC header on bpqether */
          if (receive_bpq(buf, n) < 0) {
            goto out_ttyfd;
          }
        }
      }

      /*
       * If we are in "beacon after" mode, reset the "last_bc_time" each time
       * we hear something on the channel.
       */
      if (!bc_every)
        last_bc_time = time(NULL);
    }
  out_ttyfd:

    if (udp_mode) {
      if (FD_ISSET(udpsock, &readfds)) {
        do {
          fromlen = sizeof from;
          n = recvfrom(udpsock, buf, MAX_FRAME, 0, (struct sockaddr *)&from,
                       &fromlen);
        } while (io_error(n, buf, n, READ_MSG, UDP_MODE, __LINE__));
        LOGL4("udpdata from=%s port=%d l=%d\n", inet_ntoa(from.sin_addr),
              ntohs(from.sin_port), n);
        stats.udp_in++;
        if (n > 0)
          from_ip(buf, n);
      }
    }
    /* if udp_mode */
    if (ip_mode) {
      if (FD_ISSET(sock, &readfds)) {
        do {
          fromlen = sizeof from;
          n = recvfrom(sock, buf, MAX_FRAME, 0, (struct sockaddr *)&from,
                       &fromlen);
        } while (io_error(n, buf, n, READ_MSG, IP_MODE, __LINE__));
        ipptr = (struct iphdr *)buf;
        hdr_len = 4 * ipptr->ihl;
        LOGL4("ipdata from=%s l=%d, hl=%d\n", inet_ntoa(from.sin_addr), n,
              hdr_len);
        stats.ip_in++;
        if (n > hdr_len)
          from_ip(buf + hdr_len, n - hdr_len);
      }
    }
    /* if ip_mode */
  } /* for forever */
}

/* Send an IP frame */

void send_ip(unsigned char *buf, int l, unsigned char *targetip) {
  int n;

  if (l <= 0)
    return;
  memcpy(&to.sin_addr, targetip, 4);
  memcpy(&to.sin_port, &targetip[4], 2);
  LOGL4("sendipdata to=%s %s %d l=%d\n", inet_ntoa(to.sin_addr),
        to.sin_port ? "udp" : "ip", ntohs(to.sin_port), l);
  if (to.sin_port) {
    if (udp_mode) {
      stats.udp_out++;
      do {
        n = sendto(udpsock, buf, l, 0, (struct sockaddr *)&to, sizeof to);
      } while (io_error(n, buf, l, SEND_MSG, UDP_MODE, __LINE__));
    }
  } else {
    if (ip_mode) {
      stats.ip_out++;
      do {
        n = sendto(sock, buf, l, 0, (struct sockaddr *)&to, sizeof to);
      } while (io_error(n, buf, l, SEND_MSG, IP_MODE, __LINE__));
    }
  }
}

/* Send a kiss frame */

void send_tty(unsigned char *buf, int l) {
  int n;
  unsigned char *p;
  int nc;

  if (l <= 0)
    return;
  LOGL4("sendttydata l=%d\tsent: ", l);
  stats.kiss_out++;

  p = buf;
  nc = l;
  n = 0;

  /*
   * we have to loop around here because each call to write may write a few
   * characters.  So we simply increment the buffer each time around.  If
   * we ever write no characters, we should get an error code, and io_error
   * will sleep for a fraction of a second.  Note that we are keyed to
   * the BSD 4.2 behaviour... the Sys 5 non-blocking I/O may or may not work
   * in this loop.  We may detect system 5 behaviour (this would result from
   * compile-time options) by having io_error barf when it detects an EAGAIN
   * error code.
   */
  do {
    if ((n > 0) && (n < nc)) { /* did we put only write a bit? */
      p += n;                  /* point to the new data */
      nc -= n;                 /* drop the length */
    }
    n = write(ttyfd, p, nc);
    if (n > 0) {
      if (n != nc) {
        LOGL4("%d ", n); /* no-one said loglevel 4 */
      } else {
        LOGL4("%d\n", n); /* was efficient!!! */
      }
    }
  } while (((n > 0) && (n < nc)) ||
           (io_error(n, p, nc, SEND_MSG, TTY_MODE, __LINE__)));
}
