#ifndef SQL_ACCESS_INCLUDED
#define SQL_ACCESS_INCLUDED

/* Copyright (c) 2020, MariaDB Corporation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

#include "sql_basic_types.h" // ulonglong

enum Access
{
  NO_ACL                = (0),
  SELECT_ACL            = (1UL << 0),
  INSERT_ACL            = (1UL << 1),
  UPDATE_ACL            = (1UL << 2),
  DELETE_ACL            = (1UL << 3),
  CREATE_ACL            = (1UL << 4),
  DROP_ACL              = (1UL << 5),
  RELOAD_ACL            = (1UL << 6),
  SHUTDOWN_ACL          = (1UL << 7),
  PROCESS_ACL           = (1UL << 8),
  FILE_ACL              = (1UL << 9),
  GRANT_ACL             = (1UL << 10),
  REFERENCES_ACL        = (1UL << 11),
  INDEX_ACL             = (1UL << 12),
  ALTER_ACL             = (1UL << 13),
  SHOW_DB_ACL           = (1UL << 14),
  SUPER_ACL             = (1UL << 15),
  CREATE_TMP_ACL        = (1UL << 16),
  LOCK_TABLES_ACL       = (1UL << 17),
  EXECUTE_ACL           = (1UL << 18),
  REPL_SLAVE_ACL        = (1UL << 19),
  REPL_CLIENT_ACL       = (1UL << 20),
  CREATE_VIEW_ACL       = (1UL << 21),
  SHOW_VIEW_ACL         = (1UL << 22),
  CREATE_PROC_ACL       = (1UL << 23),
  ALTER_PROC_ACL        = (1UL << 24),
  CREATE_USER_ACL       = (1UL << 25),
  EVENT_ACL             = (1UL << 26),
  TRIGGER_ACL           = (1UL << 27),
  CREATE_TABLESPACE_ACL = (1UL << 28),
  DELETE_HISTORY_ACL    = (1UL << 29),
  /*
    don't forget to update
    1. static struct show_privileges_st sys_privileges[]
    2. static const char *command_array[] and static uint command_lengths[]
    3. mysql_system_tables.sql and mysql_system_tables_fix.sql
    4. acl_init() or whatever - to define behaviour for old privilege tables
    5. sql_yacc.yy - for GRANT/REVOKE to work
    6. ALL_KNOWN_ACL
  */
  ALL_KNOWN_ACL       = (1UL << 30) - 1 // A combination of all defined bits
};


// Unary operators
static inline ulonglong operator~(const Access &access)
{
  return ~static_cast<ulonglong>(access);
}

// Comparison operators
static inline bool operator==(const Access &a, ulonglong)= delete;
static inline bool operator==(const Access &a, ulong)= delete;
static inline bool operator==(const Access &a, uint)= delete;
static inline bool operator==(const Access &a, uchar)= delete;
static inline bool operator==(const Access &a, longlong)= delete;
static inline bool operator==(const Access &a, long)= delete;
static inline bool operator==(const Access &a, int)= delete;
static inline bool operator==(const Access &a, char)= delete;
static inline bool operator==(const Access &a, bool)= delete;

static inline bool operator!=(const Access &a, ulonglong)= delete;
static inline bool operator!=(const Access &a, ulong)= delete;
static inline bool operator!=(const Access &a, uint)= delete;
static inline bool operator!=(const Access &a, uchar)= delete;
static inline bool operator!=(const Access &a, longlong)= delete;
static inline bool operator!=(const Access &a, long)= delete;
static inline bool operator!=(const Access &a, int)= delete;
static inline bool operator!=(const Access &a, char)= delete;
static inline bool operator!=(const Access &a, bool)= delete;


// Dyadic bitwise operators
static inline Access operator&(const Access &a, const Access &b)
{
  return static_cast<Access>(static_cast<ulonglong>(a) &
                             static_cast<ulonglong>(b));
}

static inline Access operator&(ulonglong a, const Access &b)
{
  return static_cast<Access>(a & static_cast<ulonglong>(b));
}

static inline Access operator&(const Access &a, ulonglong b)
{
  return static_cast<Access>(static_cast<ulonglong>(a) & b);
}

static inline Access operator|(const Access &a, const Access &b)
{
  return static_cast<Access>(static_cast<ulonglong>(a) |
                             static_cast<ulonglong>(b));
}


// Dyadyc bitwise assignment operators
static inline Access& operator&=(Access &a, const Access &b)
{
  return a= a & b;
}

static inline Access& operator&=(Access &a, ulonglong b)
{
  return a= a & b;
}

static inline Access& operator|=(Access &a, const Access &b)
{
  return a= a | b;
}




static const Access DB_ACLS
(UPDATE_ACL | SELECT_ACL | INSERT_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL |
 GRANT_ACL | REFERENCES_ACL | INDEX_ACL | ALTER_ACL | CREATE_TMP_ACL |
 LOCK_TABLES_ACL | EXECUTE_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL |
 CREATE_PROC_ACL | ALTER_PROC_ACL | EVENT_ACL | TRIGGER_ACL |
 DELETE_HISTORY_ACL);

static const Access TABLE_ACLS
(SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL |
 GRANT_ACL | REFERENCES_ACL | INDEX_ACL | ALTER_ACL | CREATE_VIEW_ACL |
 SHOW_VIEW_ACL | TRIGGER_ACL | DELETE_HISTORY_ACL);

static const Access COL_ACLS
(SELECT_ACL | INSERT_ACL | UPDATE_ACL | REFERENCES_ACL);

static const Access PROC_ACLS
(ALTER_PROC_ACL | EXECUTE_ACL | GRANT_ACL);

static const Access SHOW_PROC_ACLS
(ALTER_PROC_ACL | EXECUTE_ACL | CREATE_PROC_ACL);

static const Access GLOBAL_ACLS
(SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL |
 RELOAD_ACL | SHUTDOWN_ACL | PROCESS_ACL | FILE_ACL | GRANT_ACL |
 REFERENCES_ACL | INDEX_ACL | ALTER_ACL | SHOW_DB_ACL | SUPER_ACL |
 CREATE_TMP_ACL | LOCK_TABLES_ACL | REPL_SLAVE_ACL | REPL_CLIENT_ACL |
 EXECUTE_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL | CREATE_PROC_ACL |
 ALTER_PROC_ACL | CREATE_USER_ACL | EVENT_ACL | TRIGGER_ACL |
 CREATE_TABLESPACE_ACL | DELETE_HISTORY_ACL);

static const Access DEFAULT_CREATE_PROC_ACLS
(ALTER_PROC_ACL | EXECUTE_ACL);

static const Access SHOW_CREATE_TABLE_ACLS
(SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL |
 CREATE_ACL | DROP_ACL | ALTER_ACL | INDEX_ACL |
 TRIGGER_ACL | REFERENCES_ACL | GRANT_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL);

/**
  Table-level privileges which are automatically "granted" to everyone on
  existing temporary tables (CREATE_ACL is necessary for ALTER ... RENAME).
*/
static const Access TMP_TABLE_ACLS
(SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL |
 INDEX_ACL | ALTER_ACL);

/*
  Defines to change the above bits to how things are stored in tables
  This is needed as the 'host' and 'db' table is missing a few privileges
*/

/* Privileges that needs to be reallocated (in continous chunks) */
static const Access DB_CHUNK0 (SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL |
                   CREATE_ACL | DROP_ACL);
static const Access DB_CHUNK1 (GRANT_ACL | REFERENCES_ACL | INDEX_ACL | ALTER_ACL);
static const Access DB_CHUNK2 (CREATE_TMP_ACL | LOCK_TABLES_ACL);
static const Access DB_CHUNK3 (CREATE_VIEW_ACL | SHOW_VIEW_ACL |
                   CREATE_PROC_ACL | ALTER_PROC_ACL );
static const Access DB_CHUNK4 (EXECUTE_ACL);
static const Access DB_CHUNK5 (EVENT_ACL | TRIGGER_ACL);
static const Access DB_CHUNK6 (DELETE_HISTORY_ACL);


static inline Access fix_rights_for_db(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           (((A)       & DB_CHUNK0) |
           (((A) << 4) & DB_CHUNK1) |
           (((A) << 6) & DB_CHUNK2) |
           (((A) << 9) & DB_CHUNK3) |
           (((A) << 2) & DB_CHUNK4) |
           (((A) << 9) & DB_CHUNK5) |
           (((A) << 10) & DB_CHUNK6));
}

static inline Access get_rights_for_db(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           (((A) & DB_CHUNK0)       |
           (((A) & DB_CHUNK1) >> 4) |
           (((A) & DB_CHUNK2) >> 6) |
           (((A) & DB_CHUNK3) >> 9) |
           (((A) & DB_CHUNK4) >> 2) |
           (((A) & DB_CHUNK5) >> 9) |
           (((A) & DB_CHUNK6) >> 10));
}


#define TBL_CHUNK0 DB_CHUNK0
#define TBL_CHUNK1 DB_CHUNK1
#define TBL_CHUNK2 (CREATE_VIEW_ACL | SHOW_VIEW_ACL)
#define TBL_CHUNK3 TRIGGER_ACL
#define TBL_CHUNK4 (DELETE_HISTORY_ACL)


static inline Access fix_rights_for_table(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           (((A)        & TBL_CHUNK0) |
           (((A) <<  4) & TBL_CHUNK1) |
           (((A) << 11) & TBL_CHUNK2) |
           (((A) << 15) & TBL_CHUNK3) |
           (((A) << 16) & TBL_CHUNK4));
}


static inline Access get_rights_for_table(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           (((A) & TBL_CHUNK0)        |
           (((A) & TBL_CHUNK1) >>  4) |
           (((A) & TBL_CHUNK2) >> 11) |
           (((A) & TBL_CHUNK3) >> 15) |
           (((A) & TBL_CHUNK4) >> 16));
}


static inline Access fix_rights_for_column(const Access A)
{
  const ulonglong mask(SELECT_ACL | INSERT_ACL | UPDATE_ACL);
  return (A & mask) | static_cast<Access>((A & ~mask) << 8);
}


static inline Access get_rights_for_column(const Access A)
{
  const ulonglong mask(SELECT_ACL | INSERT_ACL | UPDATE_ACL);
  return static_cast<Access>((static_cast<ulonglong>(A) & mask) |
                             (static_cast<ulonglong>(A) >> 8));
}


static inline Access fix_rights_for_procedure(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           ((((A) << 18) & EXECUTE_ACL)   |
           (((A) << 23) & ALTER_PROC_ACL) |
           (((A) << 8) & GRANT_ACL));
}


static inline Access get_rights_for_procedure(const Access access)
{
  ulonglong A(access);
  return static_cast<Access>
           ((((A) & EXECUTE_ACL) >> 18)   |
           (((A) & ALTER_PROC_ACL) >> 23) |
           (((A) & GRANT_ACL) >> 8));
}


#endif /* SQL_ACCESS_INCLUDED */
