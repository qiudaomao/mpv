/*
 * Original author: M. Tourne
 *
 * This file is part of mpv.
 *
 * mpv is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * mpv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with mpv.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <bdsm/bdsm.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>

#include "common/msg.h"
#include "stream.h"
#include "options/m_option.h"

#include "config.h"
#if !HAVE_GPL
#error GPL only
#endif

static pthread_mutex_t smb_lock = PTHREAD_MUTEX_INITIALIZER;

struct priv {
  char *domain;
  char *user;
  char *password;
  char *server;
  char *share;
  char *filepath;
  smb_session *session;
  smb_tid shareID;
  smb_fd fd;
};

/** from https://stackoverflow.com/questions/9210528/split-string-with-delimiters-in-c */
static char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = (char**)malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

static int parse_smb_url(stream_t *stream, const char *filename, struct priv *p) {
    char **domain = &p->domain;
    char **user = &p->user;
    char **password = &p->password;
    char **server = &p->server;
    char **share = &p->share;
    char **path = &p->filepath;
    const char *start = strstr(filename, "://");
    if (start == NULL) {
        return -1;
    }
    //skip smb://
    start+=3;
    if (strstr(start, "@")==NULL) {//ex: server/share/filepath
        const char *share_start = strstr(start, "/");
        if (share_start == NULL) {
            return -1;
        }
        const size_t server_length = share_start-start;
//        printf("server_length %zd\n", server_length);
        *server = malloc(server_length+1);
        strncpy(*server, start, server_length);
        *(*server+server_length) = '\0';
        
        const char *path_start = strstr(share_start+1, "/");
        if (path_start == NULL) {
            return -1;
        }
        const size_t share_length = path_start-share_start-1;
        *share = malloc(share_length+1);
        strncpy(*share, share_start+1, share_length);
        MP_INFO(stream, "[smb] share: '%s'\n", *share);
        
        const size_t path_length = strlen(filename) - (path_start-filename);
        *path = malloc(path_length+1);
        strncpy(*path, path_start, path_length);
        *(*path+path_length)='\0';
        MP_INFO(stream, "[smb] path: '%s'\n", *path);
        return 0;
    }
    const char *share_start = strstr(start, "/");
    if (share_start==NULL) {
        return -1;
    }
    const size_t author_length = share_start-start;
//    MP_INFO("[smb] author_length %zd\n", author_length);
    //author_str is domain:user:password@server
    char *author_str = malloc(author_length+1);
    author_str[author_length]='\0';
    strncpy(author_str, start, author_length);
    MP_INFO(stream, "[smb] author_str: '%s'\n", author_str);
    
    const char *path_start = strstr(share_start+1, "/");
    if (path_start==NULL) {
        free(author_str);
        author_str = NULL;
        return -1;
    }
    const size_t path_length = strlen(filename) - (path_start-filename);
    *path = malloc(path_length+1);
    strncpy(*path, path_start, path_length);
    *(*path+path_length)='\0';
    MP_INFO(stream, "[smb] path: %s\n", *path);
    //printf("share_start: %s\n", share_start);
    //printf("path_start: %s\n", path_start);
    const size_t share_length = path_start-share_start-1;
    *share = malloc(share_length+1);
    strncpy(*share, share_start+1, share_length);
    MP_INFO(stream, "[smb] share: %s\n", *share);

    //split by @
    char *server_start = strstr(author_str, "@");
    const size_t server_length = strlen(author_str) - (server_start-author_str)-1;
    //printf("server_length: %zd\n", server_length);
    *server = malloc(server_length+1);
    strncpy(*server, server_start+1, server_length);
    *(*server+server_length)='\0';
    MP_INFO(stream, "[smb] server: %s\n", *server);
    //split by
    author_str[server_start-author_str]='\0';
    if (strlen(author_str)<3) {//handle smb://:@server/share/fielpath
        MP_WARN(stream, "[smb] handle special '%s'\n", author_str);
        return 0;
    }
    char **tokens = str_split(author_str, ':');
    size_t tokens_length = 0;
    if (tokens) {
        size_t i=0;
        while (*(tokens+i)) {
            i++;
        }
        tokens_length = i;
    }
    if (tokens_length==1) {//only user
        const size_t user_length = strlen(*tokens);
        *user = malloc(user_length + 1);
        strncpy(*user, *tokens, server_length);
        *(*user+user_length)='\0';
        MP_INFO(stream, "[smb] user: '%s'\n", *user);
    } else if (tokens_length==2) {//user:password
        const size_t user_length = strlen(*tokens);
        *user = malloc(user_length + 1);
        strncpy(*user, *tokens, server_length);
        *(*user+user_length)='\0';
        MP_INFO(stream, "[smb] user: '%s'\n", *user);

        const size_t password_length = strlen(*(tokens+1));
        *password = malloc(password_length + 1);
        strncpy(*password, *(tokens+1), password_length);
        *(*password+password_length)='\0';
        MP_INFO(stream, "[smb] password: '%s'\n", *password);
    } else if (tokens_length==3) {//domain:user:password
        const size_t domain_length = strlen(*tokens);
        *domain = malloc(domain_length + 1);
        strncpy(*domain, *tokens, domain_length);
        *(*domain+domain_length)='\0';
        MP_INFO(stream, "[smb] domain: %s\n", *domain);

        const size_t user_length = strlen(*(tokens+1));
        *user = malloc(user_length + 1);
        strncpy(*user, *(tokens+1), user_length);
        *(*user+user_length)='\0';
        MP_INFO(stream, "[smb] user: %s\n", *user);

        const size_t password_length = strlen(*(tokens+2));
        *password = malloc(password_length + 2);
        strncpy(*password, *(tokens+2), password_length);
        MP_INFO(stream, "[smb] password: %s\n", *password);
        *(*password+password_length)='\0';
    }
    free(author_str);
    if ((*server)!=NULL && (*share)!=NULL && (*path)!=NULL) {
        return 0;
    }
    return -1;
}

static void free_priv(struct priv *p) {
    if (p->domain) free(p->domain);
    if (p->user) free(p->user);
    if (p->password) free(p->password);
    if (p->server) free(p->server);
    if (p->share) free(p->share);
    if (p->filepath) free(p->filepath);
}

static int control(stream_t *s, int cmd, void *arg) {
  struct priv *p = s->priv;
  switch(cmd) {
    case STREAM_CTRL_GET_SIZE: {
      pthread_mutex_lock(&smb_lock);
      smb_stat stat = smb_fstat(p->session, p->shareID, p->filepath);
      off_t size = smb_stat_get(stat, SMB_STAT_SIZE);
      pthread_mutex_unlock(&smb_lock);
      if(size != (off_t)-1) {
        *(int64_t *)arg = size;
        return 1;
      }
    }
    break;
  }
  return STREAM_UNSUPPORTED;
}

static int seek(stream_t *s,int64_t newpos) {
  struct priv *p = s->priv;
  pthread_mutex_lock(&smb_lock);
  off_t size = smb_fseek(p->session, p->fd, newpos, SMB_SEEK_SET);
  pthread_mutex_unlock(&smb_lock);
  if(size<0) {
    return 0;
  }
  return 1;
}

static int fill_buffer(stream_t *s, char* buffer, int max_len){
  struct priv *p = s->priv;
  pthread_mutex_lock(&smb_lock);
  int r = smb_fread(p->session, p->fd, (void*)buffer, max_len);
  pthread_mutex_unlock(&smb_lock);
  return (r <= 0) ? -1 : r;
}

static int write_buffer(stream_t *s, char* buffer, int len) {
  struct priv *p = s->priv;
  int r = len;
  int wr;
  while (r > 0) {
    pthread_mutex_lock(&smb_lock);
    wr = smb_fwrite(p->session, p->fd, (void*)buffer, r);
    pthread_mutex_unlock(&smb_lock);
    if (wr <= 0)
      return -1;
    r -= wr;
    buffer += wr;
  }
  return len - r;
}

static void close_f(stream_t *s){
  struct priv *p = s->priv;
  pthread_mutex_lock(&smb_lock);
  smb_fclose(p->session, p->fd);
  smb_tree_disconnect(p->session, p->shareID);
  smb_session_destroy(p->session);
  free_priv(p);
  pthread_mutex_unlock(&smb_lock);
}

static int open_f (stream_t *stream)
{
  char *filename;

  struct priv *priv = talloc_zero(stream, struct priv);
  stream->priv = priv;

  filename = stream->url;

  bool write = stream->mode == STREAM_WRITE;

  if(!filename) {
    MP_ERR(stream, "[smb] Bad url\n");
    return STREAM_ERROR;
  }

  //filename smb://[[domain:]user[:password@]]server[/share[/path[/file]]]
  if (parse_smb_url(stream, filename, priv) != 0) {
    MP_ERR(stream, "[smb] Bad url parse failed, valid format %s\n", "smb://[[domain:]user[:password@]]server[/share[/path[/file]]]");
    free_priv(priv);
    return STREAM_ERROR;
  }
  //replace '/' with '\' in path
  char *ptr = priv->filepath;
  while (*ptr != '\0') {
    if (*ptr == '/') {
      *ptr = '\\';
    }
    ptr++;
  }
  if (priv->domain == NULL) {
    priv->domain = malloc(2);
    priv->domain[0] = ' ';
    priv->domain[1] = '\0';
  }
  if (priv->user == NULL) {
    priv->user = malloc(2);
    priv->user[0] = ' ';
    priv->user[1] = '\0';
  }
  if (priv->password == NULL) {
    priv->password = malloc(2);
    priv->password[0] = ' ';
    priv->password[1] = '\0';
  }
  pthread_mutex_lock(&smb_lock);
  smb_session *session = smb_session_new();
  if (session == NULL) {
    MP_ERR(stream, "Cannot init smb_session\n");
    free_priv(priv);
    pthread_mutex_unlock(&smb_lock);
    return STREAM_ERROR;
  }
  priv->session = session;

  smb_session_set_creds(session, priv->domain, priv->user, priv->password);
  const struct hostent *host_entry = gethostbyname(priv->server);

  if (host_entry == NULL || host_entry->h_addr_list[0] == NULL) {
    smb_session_destroy(session);
    priv->session = NULL;
    free_priv(priv);
    pthread_mutex_unlock(&smb_lock);
    return STREAM_ERROR;
  }
  //struct in_addr *addr = (struct in_addr *)host_entry->h_name;
  const struct in_addr addr = *(struct in_addr *)host_entry->h_addr_list[0];
  int result = smb_session_connect(session, "", addr.s_addr, SMB_TRANSPORT_TCP);
  if (result == 0) {
    result = smb_session_login(session);
    if (result) {
      MP_ERR(stream, "smb_session_login failed\n");
      smb_session_destroy(session);
      free_priv(priv);
      pthread_mutex_unlock(&smb_lock);
      return STREAM_ERROR;
    }
  }

  //open share
  smb_tid shareID = -1;
  int error = smb_tree_connect(session, priv->share, &shareID);
  if (error) {
    MP_ERR(stream, "smb_share [%s] open failed\n", priv->share);
    smb_session_destroy(session);
    free_priv(priv);
    pthread_mutex_unlock(&smb_lock);
    return STREAM_ERROR;
  }
  priv->shareID = shareID;

  //open file
  smb_fd fd = -1;
  uint32_t mod = 0;
  mod |= SMB_MOD_READ | SMB_MOD_READ_EXT | SMB_MOD_READ_ATTR | SMB_MOD_READ_CTL;
  if (write) {
    mod = 0;
    mod |= SMB_MOD_WRITE | SMB_MOD_WRITE_EXT | SMB_MOD_WRITE_ATTR | SMB_MOD_APPEND;
  }
  error = smb_fopen(session, shareID, priv->filepath, mod, &fd);
  if (error) {
    MP_ERR(stream, "smb_fopen failed: '%s' in share '%s'\n", priv->filepath, priv->share);
    smb_tree_disconnect(session, shareID);
    smb_session_destroy(session);
    free_priv(priv);
    pthread_mutex_unlock(&smb_lock);
    return STREAM_ERROR;
  }
  priv->fd = fd;

  //now we get fd, and then seek to start
  off_t pos = smb_fseek(session, fd, 0, SMB_SEEK_SET);
  if (pos < 0L) {
    MP_ERR(stream, "smb_fseek failed\n");
    smb_fclose(session, fd);
    smb_tree_disconnect(session, shareID);
    smb_session_destroy(session);
    free_priv(priv);
    pthread_mutex_unlock(&smb_lock);
    return STREAM_ERROR;
  }
  pthread_mutex_unlock(&smb_lock);

  smb_stat stat = smb_fstat(priv->session, priv->shareID, priv->filepath);
  off_t size = smb_stat_get(stat, SMB_STAT_SIZE);
  MP_INFO(stream, "samba file '%s' total size %lld\n", priv->filepath, size);

  stream->seekable = true;
  stream->seek = seek;
  stream->fill_buffer = fill_buffer;
  stream->write_buffer = write_buffer;
  stream->close = close_f;
  stream->control = control;
  stream->read_chunk = 128 * 1024;
  stream->streaming = true;

  return STREAM_OK;
}

const stream_info_t stream_info_smb = {
    .name = "smb",
    .open = open_f,
    .protocols = (const char*const[]){"smb", "cifs", NULL},
    .can_write = true, //who's gonna do that?
};
