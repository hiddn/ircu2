/*
 * IRC - Internet Relay Chat, ircd/m_whois.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "whocmds.h"

#include <assert.h>
#include <string.h>

/*
 * 2000-07-01: Isomer
 *  * Rewritten to make this understandable
 *  * You can nolonger /whois unregistered clients.
 *  
 *
 * General rules:
 *  /whois nick always shows the nick.
 *  /whois wild* shows the nick if:
 *   * they aren't +i and aren't on any channels.
 *   * they are on a common channel.
 *   * they aren't +i and are on a public channel. (not +p and not +s)
 *   * they aren't +i and are on a private channel. (+p but not +s)
 *  Or to look at it another way (I think):
 *   * +i users are only shown if your on a common channel.
 *   * users on +s channels only aren't shown.
 *
 *  whois doesn't show what channels a +k client is on, for the reason that
 *  /whois X or /whois W floods a user off the server. :)
 *
 * nb: if the code and this comment disagree, the codes right and I screwed
 *     up.
 */

/*
 * Send whois information for acptr to sptr
 */
static void do_whois(struct Client* sptr, struct Client *acptr)
{
  struct Client *a2cptr=0;
  struct Channel *chptr=0;
  int mlen;
  int len;
  static char buf[512];
  
  const struct User* user = acptr->user;
  const char* name = (!*acptr->name) ? "?" : acptr->name;  
  a2cptr = user->server;
  assert(user);
  send_reply(sptr, RPL_WHOISUSER, name, user->username, user->host,
		   acptr->info);

  /* Display the channels this user is on. */
  if (!IsChannelService(acptr))
  {
    struct Membership* chan;
    mlen = strlen(me.name) + strlen(sptr->name) + 12 + strlen(name);
    len = 0;
    *buf = '\0';
    for (chan = user->channel; chan; chan = chan->next_channel)
    {
       chptr = chan->channel;
       
       if (!ShowChannel(sptr, chptr))
          continue;
          
       if (acptr != sptr && IsZombie(chan))
          continue;
          
       if (len+strlen(chptr->chname) + mlen > BUFSIZE - 5) 
       {
          send_reply(sptr, SND_EXPLICIT | RPL_WHOISCHANNELS, "%s :%s", name, buf);
          *buf = '\0';
          len = 0;
       }
       if (IsDeaf(acptr))
         *(buf + len++) = '-';
       if (is_chan_op(acptr, chptr))
         *(buf + len++) = '@';
       else if (has_voice(acptr, chptr))
         *(buf + len++) = '+';
       else if (IsZombie(chan))
         *(buf + len++) = '!';
       if (len)
          *(buf + len) = '\0';
       strcpy(buf + len, chptr->chname);
       len += strlen(chptr->chname);
       strcat(buf + len, " ");
       len++;
     }
     if (buf[0] != '\0')
        send_reply(sptr, RPL_WHOISCHANNELS, name, buf);
  }
  send_reply(sptr, RPL_WHOISSERVER, name, a2cptr->name, a2cptr->info);

  if (user)
  {
    if (user->away)
       send_reply(sptr, RPL_AWAY, name, user->away);

    if (IsAnOper(acptr))
       send_reply(sptr, RPL_WHOISOPERATOR, name);
   
    /* Hint: if your looking to add more flags to a user, eg +h, here's
     *       probably a good place to add them :)
     */
     
    if (MyConnect(acptr))
       send_reply(sptr, RPL_WHOISIDLE, name, CurrentTime - user->last, 
                  acptr->firsttime);
  }
}

/*
 * Search and return as many people as matched by the wild 'nick'.
 * returns the number of people found (or, obviously, 0, if none where
 * found).
 */
static int do_wilds(struct Client* sptr,char *nick,int count)
{
  struct Client *acptr; /* Current client we're concidering */
  struct User *user; 	/* the user portion of the client */
  char *name; 		/* the name of this client */
  struct Membership* chan; 
  int invis; 		/* does +i apply? */
  int member;		/* Is this user on any channels? */
  int showperson;       /* Should we show this person? */
  int found = 0 ;	/* How many were found? */
  
  /* Ech! This is hidious! */
  for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
      acptr = acptr->next)
  {
    if (!IsRegistered(acptr)) 
      continue;
      
    if (IsServer(acptr))
      continue;
    /*
     * I'm always last :-) and acptr->next == 0!!
     *
     * Isomer: Does this strike anyone else as being a horrible hidious
     *         hack?
     */
    if (IsMe(acptr)) {
      assert(!acptr->next);
      break;
    }
    
    /*
     * 'Rules' established for sending a WHOIS reply:
     *
     * - if wildcards are being used dont send a reply if
     *   the querier isnt any common channels and the
     *   client in question is invisible.
     *
     * - only send replies about common or public channels
     *   the target user(s) are on;
     */
    user = acptr->user;
    name = (!*acptr->name) ? "?" : acptr->name;
    assert(user);

    invis = (acptr != sptr) && IsInvisible(acptr);
    member = (user && user->channel) ? 1 : 0;
    showperson = !invis && !member;
    
    /* Should we show this person now? */
    if (showperson) {
    	found++;
    	do_whois(sptr,acptr);
    	if (count+found>MAX_WHOIS_LINES)
    	  return found;
    	continue;
    }
    
    /* Step through the channels this user is on */
    for (chan = user->channel; chan; chan = chan->next_channel)
    {
      struct Channel *chptr = chan->channel;

      /* If this is a public channel, show the person */
      if (!invis && PubChannel(chptr)) {
        showperson = 1;
        break;
      }
      
      /* if this channel is +p and not +s, show them */
      if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr)) {
          showperson = 1;
          break;
      }
      
      member = find_channel_member(sptr, chptr) ? 1 : 0;
      if (invis && !member)
        continue;

      /* If sptr isn't really on this channel, skip it */
      if (IsZombie(chan))
        continue;
       
      /* Is this a common channel? */ 
      if (member) {
        showperson = 1;
        break;
      }
    } /* of for (chan in channels) */
    
    /* Don't show this person */
    if (!showperson)
      continue;
      
    do_whois(sptr,acptr);
    found++;
    if (count+found>MAX_WHOIS_LINES)
       return found;  
  } /* of global client list */
  
  return found;
}

/*
 * m_whois - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server, or a nickname representing a server to target.
 * parv[2] = nickname masklist
 */
int m_whois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           nick;
  char*           tmp;
  char*           p = 0;
  int             found = 0;
  int		  total = 0;

  if (parc < 2)
  {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
     * it with the correct servername - as is needed by hunt_server().
     * This is the secret behind the /whois nick nick trick.
     */
    acptr = FindUser(parv[1]);
    if (acptr)
      parv[1] = acptr->user->server->name;
    if (hunt_server_cmd(sptr, CMD_WHOIS, cptr, 0, "%C :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int wilds;

    found = 0;
    
    collapse(nick);
    
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    if (!wilds) {
      struct Client *acptr = 0;
      /* No wildcards */
      acptr = FindUser(nick);
      if (acptr && !IsServer(acptr)) {
        do_whois(sptr,acptr);
        found = 1;
      }
    }
    else /* wilds */
    	found=do_wilds(sptr,nick,total);

    if (!found)
      send_reply(sptr, ERR_NOSUCHNICK, nick);
    total+=found;
    if (total >= MAX_WHOIS_LINES) {
      send_reply(sptr, ERR_QUERYTOOLONG, parv[1]);
      break;
    }
    if (p)
      p[-1] = ',';
  } /* of tokenised parm[1] */
  send_reply(sptr, RPL_ENDOFWHOIS, parv[1]);

  return 0;
}

/*
 * ms_whois - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server, or a nickname representing a server to target.
 * parv[2] = nickname masklist
 */
int ms_whois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           nick;
  char*           tmp;
  char*           p = 0;
  int             found = 0;
  int		  total = 0;

  if (parc < 2)
  {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
     * it with the correct servername - as is needed by hunt_server().
     * This is the secret behind the /whois nick nick trick.
     */
    acptr = FindUser(parv[1]);
    if (acptr)
      parv[1] = acptr->user->server->name;
    if (hunt_server_cmd(sptr, CMD_WHOIS, cptr, 0, "%C :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    struct Client *acptr = 0;

    found = 0;
    
    collapse(nick);
    

    acptr = FindUser(nick);
    if (acptr && !IsServer(acptr)) {
      found++;
      do_whois(sptr,acptr);
    }

    if (!found)
      send_reply(sptr, ERR_NOSUCHNICK, nick);
      
    total+=found;
      
    if (total >= MAX_WHOIS_LINES) {
      send_reply(sptr, ERR_QUERYTOOLONG, parv[1]);
      break;
    }
      
    if (p)
      p[-1] = ',';
  } /* of tokenised parm[1] */
  send_reply(sptr, RPL_ENDOFWHOIS, parv[1]);

  return 0;
}