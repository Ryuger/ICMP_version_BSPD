#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sqlite3.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

typedef unsigned __int64 u64;
typedef unsigned int u32;
typedef unsigned short u16;

typedef enum { ST_UNKNOWN=0, ST_UP=1, ST_DOWN=2 } Status;

typedef struct Host {
    volatile LONG used;
    volatile LONG enabled;

    char name[64];
    char group[64];
    char subgroup[64];
    ULONG ip;

    volatile LONG interval_ms;
    volatile LONG timeout_ms;
    volatile LONG down_threshold;

    volatile LONG ok;
    volatile LONG fail;
    volatile LONG consec_fail;

    volatile LONG last_rtt;
    volatile LONG min_rtt;
    volatile LONG max_rtt;
    volatile LONG samples;
    volatile LONGLONG sum_rtt;

    volatile LONG st;
    volatile LONGLONG last_change_qpc;

    SRWLOCK hist_lock;
    u32* hist_t;
    u16* hist_r;
    u32 hist_cap, hist_pos, hist_count;

    volatile LONG sched_gen;
    volatile LONG queued;
} Host;

typedef struct SchedNode {
    int host_id;
    u64 due_qpc;
    LONG gen;
} SchedNode;

static LARGE_INTEGER g_qpf;
static HANDLE g_icmp = NULL;

static Host* g_hosts = NULL;
static int g_hosts_cap = 20000;
static volatile LONG g_n_hosts = 0;
static SRWLOCK g_hosts_lock;

static SchedNode* g_heap = NULL;
static int g_heap_n = 0;
static int g_heap_cap = 0;
static SRWLOCK g_sched_lock;

static u32 g_default_interval_ms = 1000;
static u32 g_default_timeout_ms = 1000;
static u32 g_default_down_threshold = 3;
static u32 g_history_len = 512;
static const char* g_db_path = "icmpmon.db";
static volatile LONG g_db_enabled = 1;

static HANDLE g_con = NULL;


static __forceinline u64 qpc_now(void){ LARGE_INTEGER t; QueryPerformanceCounter(&t); return (u64)t.QuadPart; }
static __forceinline u64 ms_to_qpc(u32 ms){ return ((u64)ms * (u64)g_qpf.QuadPart) / 1000ULL; }
static __forceinline double qpc_to_sec(u64 dt){ return (double)dt / (double)g_qpf.QuadPart; }

static void sleep_until_qpc(u64 due){
    for(;;){
        u64 now = qpc_now();
        if(now >= due) return;
        u64 diff = due - now;
        DWORD ms = (DWORD)((diff * 1000ULL) / (u64)g_qpf.QuadPart);
        if(ms > 2) Sleep(ms - 2); else Sleep(0);
    }
}

static int is_space_a(char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; }

static char* trim_a(char* s){
    char* e;
    while(*s && is_space_a(*s)) s++;
    if(!*s) return s;
    e = s + strlen(s) - 1;
    while(e >= s && is_space_a(*e)){
        *e = 0;
        if(e == s) break;
        e--;
    }
    return s;
}

static int resolve_v4(const char* s, ULONG* out_ip){
    struct addrinfo hints, *ai = 0;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(s, 0, &hints, &ai) != 0 || !ai) return 0;
    *out_ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.S_un.S_addr;
    freeaddrinfo(ai);
    return 1;
}

static void host_reset_stats(Host* h){
    h->ok = h->fail = h->consec_fail = 0;
    h->last_rtt = 0;
    h->min_rtt = 0x7fffffff;
    h->max_rtt = 0;
    h->samples = 0;
    h->sum_rtt = 0;
    h->st = ST_UNKNOWN;
    h->last_change_qpc = 0;
    AcquireSRWLockExclusive(&h->hist_lock);
    h->hist_pos = h->hist_count = 0;
    if(h->hist_t) ZeroMemory(h->hist_t, sizeof(u32)*h->hist_cap);
    if(h->hist_r) ZeroMemory(h->hist_r, sizeof(u16)*h->hist_cap);
    ReleaseSRWLockExclusive(&h->hist_lock);
}

static void host_init_slot(Host* h){
    ZeroMemory(h, sizeof(*h));
    InitializeSRWLock(&h->hist_lock);
    h->hist_cap = g_history_len;
    h->hist_t = (u32*)calloc(g_history_len, sizeof(u32));
    h->hist_r = (u16*)calloc(g_history_len, sizeof(u16));
    h->used = 0;
    h->enabled = 1;
    h->sched_gen = 1;
    h->interval_ms = (LONG)g_default_interval_ms;
    h->timeout_ms = (LONG)g_default_timeout_ms;
    h->down_threshold = (LONG)g_default_down_threshold;
    host_reset_stats(h);
}

static int parse_host_line(char* line, char* group, char* subgroup, char* name, u32* interval_ms){
    char* p = trim_a(line);
    if(!*p || *p=='#') return 0;

    char* tok[4] = {0};
    int n = 0;
    tok[n++] = p;
    while(*p && n < 4){
        if(*p == ';'){
            *p = 0;
            tok[n++] = p + 1;
        }
        p++;
    }

    for(int i=0;i<n;i++) tok[i] = trim_a(tok[i]);

    if(n == 1){
        if(!*tok[0]) return 0;
        _snprintf_s(group, 64, _TRUNCATE, "Default");
        _snprintf_s(subgroup, 64, _TRUNCATE, "Main");
        _snprintf_s(name, 64, _TRUNCATE, "%s", tok[0]);
        *interval_ms = g_default_interval_ms;
        return 1;
    }
    if(n >= 3){
        if(!*tok[2]) return 0;
        _snprintf_s(group, 64, _TRUNCATE, "%s", tok[0]);
        _snprintf_s(subgroup, 64, _TRUNCATE, "%s", tok[1]);
        _snprintf_s(name, 64, _TRUNCATE, "%s", tok[2]);
        if(n >= 4){
            u32 v = (u32)strtoul(tok[3], 0, 10);
            *interval_ms = v ? v : g_default_interval_ms;
        }else *interval_ms = g_default_interval_ms;
        return 1;
    }
    return 0;
}

static int add_host(const char* name, const char* group, const char* subgroup, ULONG ip, u32 interval_ms, u32 timeout_ms, u32 down_thr){
    int id = -1;
    AcquireSRWLockExclusive(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        if(!g_hosts[i].used){ id = i+1; break; }
    }
    if(id > 0){
        Host* h = &g_hosts[id-1];
        h->used = 1;
        h->enabled = 1;
        h->ip = ip;
        _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name);
        _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", group && *group ? group : "Default");
        _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", subgroup && *subgroup ? subgroup : "Main");
        h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms);
        h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms);
        h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr);
        InterlockedIncrement(&h->sched_gen);
        host_reset_stats(h);
        InterlockedIncrement(&g_n_hosts);
    }
    ReleaseSRWLockExclusive(&g_hosts_lock);
    return id;
}

static int edit_host(int id, const char* name, const char* group, const char* subgroup, const char* addr, int set_interval, u32 interval_ms, int set_timeout, u32 timeout_ms, int set_down, u32 down_thr, int set_enabled, int enabled){
    if(id < 1 || id > g_hosts_cap) return 0;
    AcquireSRWLockExclusive(&g_hosts_lock);
    Host* h = &g_hosts[id-1];
    if(!h->used){ ReleaseSRWLockExclusive(&g_hosts_lock); return 0; }

    if(name && *name) _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name);
    if(group && *group) _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", group);
    if(subgroup && *subgroup) _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", subgroup);
    if(addr && *addr){
        ULONG ip;
        if(resolve_v4(addr, &ip)) h->ip = ip;
    }
    if(set_interval){ h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms); InterlockedIncrement(&h->sched_gen); }
    if(set_timeout){ h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms); }
    if(set_down){ h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr); }
    if(set_enabled){ h->enabled = enabled ? 1 : 0; InterlockedIncrement(&h->sched_gen); }
    ReleaseSRWLockExclusive(&g_hosts_lock);
    return 1;
}

static int delete_host(int id){
    if(id < 1 || id > g_hosts_cap) return 0;
    AcquireSRWLockExclusive(&g_hosts_lock);
    Host* h = &g_hosts[id-1];
    if(!h->used){ ReleaseSRWLockExclusive(&g_hosts_lock); return 0; }
    h->used = 0;
    h->enabled = 0;
    h->queued = 0;
    InterlockedIncrement(&h->sched_gen);
    host_reset_stats(h);
    InterlockedDecrement(&g_n_hosts);
    ReleaseSRWLockExclusive(&g_hosts_lock);
    return 1;
}

static int load_hosts_file(const char* path){
    FILE* f = fopen(path, "rb");
    if(!f){ fprintf(stderr, "hosts: cannot open '%s'\n", path); return -1; }
    int n = 0;
    char line[512];
    while(fgets(line, sizeof(line), f)){
        char g[64], sg[64], name[64];
        u32 interval_ms;
        if(!parse_host_line(line, g, sg, name, &interval_ms)) continue;
        ULONG ip;
        if(!resolve_v4(name, &ip)) continue;
        if(add_host(name, g, sg, ip, interval_ms, g_default_timeout_ms, g_default_down_threshold) > 0) n++;
    }
    fclose(f);
    return n;
}

static __forceinline void hist_push(Host* h, u32 t_epoch, u16 rtt_code){
    AcquireSRWLockExclusive(&h->hist_lock);
    h->hist_t[h->hist_pos] = t_epoch;
    h->hist_r[h->hist_pos] = rtt_code;
    h->hist_pos = (h->hist_pos + 1u) % h->hist_cap;
    if(h->hist_count < h->hist_cap) h->hist_count++;
    ReleaseSRWLockExclusive(&h->hist_lock);
}

static __forceinline void hswap(SchedNode* a, SchedNode* b){ SchedNode t=*a; *a=*b; *b=t; }
static void heap_up(int i){
    while(i>0){ int p=(i-1)>>1; if(g_heap[p].due_qpc <= g_heap[i].due_qpc) break; hswap(&g_heap[p], &g_heap[i]); i=p; }
}
static void heap_dn(int i){
    for(;;){
        int l=i*2+1, r=l+1, m=i;
        if(l<g_heap_n && g_heap[l].due_qpc < g_heap[m].due_qpc) m=l;
        if(r<g_heap_n && g_heap[r].due_qpc < g_heap[m].due_qpc) m=r;
        if(m==i) break;
        hswap(&g_heap[m], &g_heap[i]); i=m;
    }
}
static void heap_push(SchedNode x){
    if(g_heap_n >= g_heap_cap) return;
    g_heap[g_heap_n] = x;
    heap_up(g_heap_n++);
}
static SchedNode heap_pop(void){
    SchedNode t = g_heap[0];
    g_heap[0] = g_heap[--g_heap_n];
    if(g_heap_n>0) heap_dn(0);
    return t;
}

typedef struct Task { int host_id; } Task;
static Task* g_task_q = NULL;
static LONG g_q_cap = 0;
static LONG g_q_head = 0;
static LONG g_q_tail = 0;
static LONG g_q_count = 0;
static SRWLOCK g_q_lock;
static HANDLE g_sem = NULL;

static int q_post(int host_id){
    int ok = 0;
    AcquireSRWLockExclusive(&g_q_lock);
    if(g_q_count < g_q_cap){
        g_task_q[g_q_tail].host_id = host_id;
        g_q_tail = (g_q_tail + 1) % g_q_cap;
        g_q_count++;
        ok = 1;
    }
    ReleaseSRWLockExclusive(&g_q_lock);
    if(ok) ReleaseSemaphore(g_sem, 1, NULL);
    return ok;
}
static int q_take(void){
    int id = 0;
    WaitForSingleObject(g_sem, INFINITE);
    AcquireSRWLockExclusive(&g_q_lock);
    if(g_q_count > 0){
        id = g_task_q[g_q_head].host_id;
        g_q_head = (g_q_head + 1) % g_q_cap;
        g_q_count--;
    }
    ReleaseSRWLockExclusive(&g_q_lock);
    return id;
}

/* DB */
typedef enum { DB_SAMPLE=1, DB_EVENT=2, DB_DELETE_HOST=3, DB_STOP=4 } DbType;
typedef struct DbMsg {
    SLIST_ENTRY e;
    DbType type;
    u32 ts;
    int host_id;
    int rtt_ms;
    int timeout_ms;
    int old_st;
    int new_st;
    char detail[64];
} DbMsg;

static SLIST_HEADER g_dbq;
static HANDLE g_dbsem = NULL;
static void db_post(DbMsg* m){ InterlockedPushEntrySList(&g_dbq, &m->e); ReleaseSemaphore(g_dbsem, 1, NULL); }
static DbMsg* db_take(void){ WaitForSingleObject(g_dbsem, INFINITE); return (DbMsg*)InterlockedPopEntrySList(&g_dbq); }

static int db_exec(sqlite3* db, const char* sql){
    char* err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if(rc != SQLITE_OK){ fprintf(stderr, "SQLite exec error: %s\n", err ? err : "(null)"); sqlite3_free(err); }
    return rc;
}

static void db_init(void){
    sqlite3* db = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return; }
    db_exec(db, "PRAGMA journal_mode=WAL;");
    db_exec(db,
        "CREATE TABLE IF NOT EXISTS hosts(host_id INTEGER PRIMARY KEY,name TEXT,ip TEXT,grp TEXT,subgrp TEXT,interval_ms INTEGER,timeout_ms INTEGER,down_threshold INTEGER,enabled INTEGER);"
        "CREATE TABLE IF NOT EXISTS samples(ts INTEGER,host_id INTEGER,rtt_ms INTEGER NULL,timeout_ms INTEGER);"
        "CREATE TABLE IF NOT EXISTS events(ts INTEGER,host_id INTEGER,old_status INTEGER,new_status INTEGER,detail TEXT);"
    );
    sqlite3_close(db);
}

static void db_sync_hosts(void){
    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return; }
    sqlite3_busy_timeout(db, 3000);
    if(db_exec(db, "BEGIN;") != SQLITE_OK){ sqlite3_close(db); return; }
    if(sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO hosts(host_id,name,ip,grp,subgrp,interval_ms,timeout_ms,down_threshold,enabled) VALUES(?,?,?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK){
        db_exec(db, "ROLLBACK;");
        sqlite3_close(db);
        return;
    }

    int ok = 1;
    AcquireSRWLockShared(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        Host* h = &g_hosts[i];
        if(!h->used) continue;
        char ipbuf[32];
        struct in_addr ia; ia.S_un.S_addr = h->ip;
        _snprintf_s(ipbuf, sizeof(ipbuf), _TRUNCATE, "%s", inet_ntoa(ia));
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(st, 1, i+1);
        sqlite3_bind_text(st, 2, h->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ipbuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, h->group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, h->subgroup, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, h->interval_ms);
        sqlite3_bind_int(st, 7, h->timeout_ms);
        sqlite3_bind_int(st, 8, h->down_threshold);
        sqlite3_bind_int(st, 9, h->enabled);
        if(sqlite3_step(st) != SQLITE_DONE){ ok = 0; break; }
    }
    ReleaseSRWLockShared(&g_hosts_lock);

    sqlite3_finalize(st);
    if(ok) db_exec(db, "COMMIT;");
    else db_exec(db, "ROLLBACK;");
    sqlite3_close(db);
}

static void db_upsert_host(int id){
    if(id < 1 || id > g_hosts_cap) return;

    Host snap;
    ZeroMemory(&snap, sizeof(snap));
    AcquireSRWLockShared(&g_hosts_lock);
    Host* h = &g_hosts[id-1];
    if(h->used) snap = *h;
    ReleaseSRWLockShared(&g_hosts_lock);
    if(!snap.used) return;

    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return; }
    sqlite3_busy_timeout(db, 3000);
    if(sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO hosts(host_id,name,ip,grp,subgrp,interval_ms,timeout_ms,down_threshold,enabled) VALUES(?,?,?,?,?,?,?,?,?)", -1, &st, NULL) == SQLITE_OK){
        char ipbuf[32];
        struct in_addr ia; ia.S_un.S_addr = snap.ip;
        _snprintf_s(ipbuf, sizeof(ipbuf), _TRUNCATE, "%s", inet_ntoa(ia));
        sqlite3_bind_int(st, 1, id);
        sqlite3_bind_text(st, 2, snap.name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ipbuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, snap.group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, snap.subgroup, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, snap.interval_ms);
        sqlite3_bind_int(st, 7, snap.timeout_ms);
        sqlite3_bind_int(st, 8, snap.down_threshold);
        sqlite3_bind_int(st, 9, snap.enabled);
        sqlite3_step(st);
    }
    if(st) sqlite3_finalize(st);
    sqlite3_close(db);
}

static int db_load_hosts(void){
    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    int n = 0;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return 0; }
    if(sqlite3_prepare_v2(db, "SELECT host_id,name,ip,grp,subgrp,interval_ms,timeout_ms,down_threshold,enabled FROM hosts ORDER BY host_id", -1, &st, NULL) != SQLITE_OK){ sqlite3_close(db); return 0; }

    AcquireSRWLockExclusive(&g_hosts_lock);
    while(sqlite3_step(st) == SQLITE_ROW){
        int id = sqlite3_column_int(st, 0);
        const unsigned char* name = sqlite3_column_text(st, 1);
        const unsigned char* iptxt = sqlite3_column_text(st, 2);
        const unsigned char* grp = sqlite3_column_text(st, 3);
        const unsigned char* sub = sqlite3_column_text(st, 4);
        int interval_ms = sqlite3_column_int(st, 5);
        int timeout_ms = sqlite3_column_int(st, 6);
        int down_thr = sqlite3_column_int(st, 7);
        int enabled = sqlite3_column_int(st, 8);

        if(id < 1 || id > g_hosts_cap) continue;
        Host* h = &g_hosts[id-1];
        ULONG ip = 0;
        if(iptxt && *iptxt){
            struct in_addr ia;
            if(InetPtonA(AF_INET, (const char*)iptxt, &ia) == 1) ip = ia.S_un.S_addr;
        }
        if(ip == 0){
            if(!resolve_v4((const char*)(name ? name : (const unsigned char*)""), &ip)) continue;
        }

        h->used = 1;
        h->enabled = enabled ? 1 : 0;
        h->ip = ip;
        _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name ? (const char*)name : "host");
        _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", grp ? (const char*)grp : "Default");
        _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", sub ? (const char*)sub : "Main");
        h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms);
        h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms);
        h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr);
        h->sched_gen = 1;
        h->queued = 0;
        host_reset_stats(h);
        InterlockedIncrement(&g_n_hosts);
        n++;
    }
    ReleaseSRWLockExclusive(&g_hosts_lock);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return n;
}

static DWORD WINAPI db_thread(void* _){
    (void)_;
    sqlite3* db = NULL;
    sqlite3_stmt* st_sample = NULL;
    sqlite3_stmt* st_event = NULL;
    sqlite3_stmt* st_del_hosts = NULL;
    sqlite3_stmt* st_del_samples = NULL;
    sqlite3_stmt* st_del_events = NULL;
    int tx_open = 0;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ InterlockedExchange(&g_db_enabled, 0); if(db) sqlite3_close(db); return 0; }
    sqlite3_busy_timeout(db, 3000);
    if(sqlite3_prepare_v2(db, "INSERT INTO samples(ts,host_id,rtt_ms,timeout_ms) VALUES(?,?,?,?)", -1, &st_sample, NULL) != SQLITE_OK ||
       sqlite3_prepare_v2(db, "INSERT INTO events(ts,host_id,old_status,new_status,detail) VALUES(?,?,?,?,?)", -1, &st_event, NULL) != SQLITE_OK ||
       sqlite3_prepare_v2(db, "DELETE FROM hosts WHERE host_id=?", -1, &st_del_hosts, NULL) != SQLITE_OK ||
       sqlite3_prepare_v2(db, "DELETE FROM samples WHERE host_id=?", -1, &st_del_samples, NULL) != SQLITE_OK ||
       sqlite3_prepare_v2(db, "DELETE FROM events WHERE host_id=?", -1, &st_del_events, NULL) != SQLITE_OK){
        if(st_sample) sqlite3_finalize(st_sample);
        if(st_event) sqlite3_finalize(st_event);
        if(st_del_hosts) sqlite3_finalize(st_del_hosts);
        if(st_del_samples) sqlite3_finalize(st_del_samples);
        if(st_del_events) sqlite3_finalize(st_del_events);
        sqlite3_close(db);
        InterlockedExchange(&g_db_enabled, 0);
        return 0;
    }
    if(db_exec(db, "BEGIN;") == SQLITE_OK) tx_open = 1;
    int batch = 0;
    for(;;){
        DbMsg* m = db_take();
        if(!m) continue;
        if(m->type == DB_STOP){ free(m); break; }
        if(!tx_open && db_exec(db, "BEGIN;") == SQLITE_OK) tx_open = 1;
        if(m->type == DB_SAMPLE){
            sqlite3_reset(st_sample);
            sqlite3_clear_bindings(st_sample);
            sqlite3_bind_int(st_sample,1,m->ts);
            sqlite3_bind_int(st_sample,2,m->host_id);
            if(m->rtt_ms>=0) sqlite3_bind_int(st_sample,3,m->rtt_ms); else sqlite3_bind_null(st_sample,3);
            sqlite3_bind_int(st_sample,4,m->timeout_ms);
            sqlite3_step(st_sample);
            sqlite3_reset(st_sample);
        }else if(m->type == DB_EVENT){
            sqlite3_reset(st_event);
            sqlite3_clear_bindings(st_event);
            sqlite3_bind_int(st_event,1,m->ts);
            sqlite3_bind_int(st_event,2,m->host_id);
            sqlite3_bind_int(st_event,3,m->old_st);
            sqlite3_bind_int(st_event,4,m->new_st);
            sqlite3_bind_text(st_event,5,m->detail,-1,SQLITE_TRANSIENT);
            sqlite3_step(st_event);
            sqlite3_reset(st_event);
        }else if(m->type == DB_DELETE_HOST){
            sqlite3_reset(st_del_hosts);
            sqlite3_clear_bindings(st_del_hosts);
            sqlite3_bind_int(st_del_hosts,1,m->host_id);
            sqlite3_step(st_del_hosts);
            sqlite3_reset(st_del_hosts);

            sqlite3_reset(st_del_samples);
            sqlite3_clear_bindings(st_del_samples);
            sqlite3_bind_int(st_del_samples,1,m->host_id);
            sqlite3_step(st_del_samples);
            sqlite3_reset(st_del_samples);

            sqlite3_reset(st_del_events);
            sqlite3_clear_bindings(st_del_events);
            sqlite3_bind_int(st_del_events,1,m->host_id);
            sqlite3_step(st_del_events);
            sqlite3_reset(st_del_events);
        }
        free(m);
        batch++;
        if(tx_open && batch >= 1000){
            if(db_exec(db, "COMMIT;") == SQLITE_OK) tx_open = 0;
            else { db_exec(db, "ROLLBACK;"); tx_open = 0; }
            batch = 0;
        }
    }
    sqlite3_reset(st_sample);
    sqlite3_reset(st_event);
    if(tx_open){
        if(db_exec(db, "COMMIT;") != SQLITE_OK) db_exec(db, "ROLLBACK;");
    }
    if(st_sample) sqlite3_finalize(st_sample);
    if(st_event) sqlite3_finalize(st_event);
    if(st_del_hosts) sqlite3_finalize(st_del_hosts);
    if(st_del_samples) sqlite3_finalize(st_del_samples);
    if(st_del_events) sqlite3_finalize(st_del_events);
    sqlite3_close(db);
    return 0;
}

static void db_emit_sample(int host_id, u32 ts, int rtt_ms, int timeout_ms){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1,sizeof(DbMsg)); if(!m) return;
    m->type = DB_SAMPLE; m->host_id = host_id; m->ts = ts; m->rtt_ms = rtt_ms; m->timeout_ms = timeout_ms;
    db_post(m);
}
static void db_emit_event(int host_id, u32 ts, int old_st, int new_st, const char* detail){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1,sizeof(DbMsg)); if(!m) return;
    m->type = DB_EVENT; m->host_id = host_id; m->ts = ts; m->old_st = old_st; m->new_st = new_st;
    _snprintf_s(m->detail,sizeof(m->detail),_TRUNCATE,"%s",detail?detail:"");
    db_post(m);
}
static void db_emit_delete_host(int host_id){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1,sizeof(DbMsg)); if(!m) return;
    m->type = DB_DELETE_HOST; m->host_id = host_id;
    db_post(m);
}

static void update_minmax(Host* h, u32 rtt){
    LONG cur = h->min_rtt;
    while((u32)cur > rtt){ if(InterlockedCompareExchange(&h->min_rtt,(LONG)rtt,cur)==cur) break; cur = h->min_rtt; }
    cur = h->max_rtt;
    while((u32)cur < rtt){ if(InterlockedCompareExchange(&h->max_rtt,(LONG)rtt,cur)==cur) break; cur = h->max_rtt; }
}

static DWORD WINAPI worker(void* _){
    (void)_;
    for(;;){
        int id = q_take();
        if(id <= 0) break;

        if(id < 1 || id > g_hosts_cap) continue;
        Host* h = &g_hosts[id-1];
        InterlockedExchange(&h->queued, 0);
        if(!h->used || !h->enabled) continue;

        ULONG ip = h->ip;
        int timeout_ms = h->timeout_ms;
        int down_thr = h->down_threshold;

        char payload[32];
        char replybuf[sizeof(ICMP_ECHO_REPLY)+32];
        ZeroMemory(payload,sizeof(payload));
        DWORD rc = IcmpSendEcho(g_icmp, ip, payload, (WORD)sizeof(payload), NULL, replybuf, sizeof(replybuf), timeout_ms);
        ICMP_ECHO_REPLY* rep = (ICMP_ECHO_REPLY*)replybuf;

        u64 now_q = qpc_now();
        u32 now_epoch = (u32)time(NULL);

        if(rc && rep->Status == IP_SUCCESS){
            u32 rtt = rep->RoundTripTime;
            InterlockedIncrement(&h->ok);
            InterlockedExchange(&h->consec_fail, 0);
            InterlockedExchange(&h->last_rtt, (LONG)rtt);
            InterlockedIncrement(&h->samples);
            InterlockedAdd64(&h->sum_rtt, (LONGLONG)rtt);
            update_minmax(h, rtt);
            hist_push(h, now_epoch, (u16)(rtt > 65534 ? 65534 : rtt));
            db_emit_sample(id, now_epoch, (int)rtt, timeout_ms);
            int prev = InterlockedExchange(&h->st, ST_UP);
            if(prev != ST_UP){
                InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                db_emit_event(id, now_epoch, prev, ST_UP, "up");
            }
        }else{
            LONG cf = InterlockedIncrement(&h->consec_fail);
            InterlockedIncrement(&h->fail);
            hist_push(h, now_epoch, 0xFFFFu);
            db_emit_sample(id, now_epoch, -1, timeout_ms);
            if((u32)cf >= (u32)down_thr){
                int prev = InterlockedExchange(&h->st, ST_DOWN);
                if(prev != ST_DOWN){
                    InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                    db_emit_event(id, now_epoch, prev, ST_DOWN, "down");
                }
            }
        }
    }
    return 0;
}

static const char* st_name(int s){ return s==ST_UP?"UP":(s==ST_DOWN?"DOWN":"UNK"); }
static void con_move(short x, short y){ COORD c; c.X=x; c.Y=y; SetConsoleCursorPosition(g_con, c); }
static void con_clear_all(void){
    CONSOLE_SCREEN_BUFFER_INFO csbi; DWORD n,w;
    if(!GetConsoleScreenBufferInfo(g_con,&csbi)) return;
    n=(DWORD)(csbi.dwSize.X*csbi.dwSize.Y);
    FillConsoleOutputCharacterA(g_con,' ',n,(COORD){0,0},&w);
    FillConsoleOutputAttribute(g_con,csbi.wAttributes,n,(COORD){0,0},&w);
}
static void render_console(void){
    u64 now = qpc_now();
    unsigned up=0, down=0, unk=0;
    for(int i=0;i<g_hosts_cap;i++) if(g_hosts[i].used){ int s=g_hosts[i].st; if(s==ST_UP) up++; else if(s==ST_DOWN) down++; else unk++; }
    con_move(0,0);
    printf("icmpmon hosts=%ld up=%u down=%u unk=%u\n", g_n_hosts, up, down, unk);
    printf("%-4s %-20s %-10s %-10s %-5s %-6s %-6s %-6s %-6s\n","id","group","subgroup","host","st","int","tout","ok","fail");
    for(int i=0;i<g_hosts_cap;i++){
        Host* h=&g_hosts[i]; if(!h->used) continue;
        LONG minr = h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
        double since = h->last_change_qpc? qpc_to_sec(now-(u64)h->last_change_qpc):0;
        printf("%-4d %-20s %-10s %-10s %-5s %-6ld %-6ld %-6ld %-6ld last=%ld avg=%lld min/max=%ld/%ld since=%.0f\n",
            i+1,h->group,h->subgroup,h->name,st_name(h->st),h->interval_ms,h->timeout_ms,h->ok,h->fail,h->last_rtt,
            h->samples? (h->sum_rtt/h->samples):0,minr,h->max_rtt,since);
    }
}

int main(int argc, char** argv){
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);

    char** pargv = (char**)malloc((size_t)argc * sizeof(char*));
    if(!pargv) return 1;
    int parc = 1;
    pargv[0] = argv[0];
    for(int i=1;i<argc;i++){
        const char* a = argv[i];
        if(strcmp(a, "--http") == 0){
            fprintf(stderr, "Embedded HTTP interface is disabled by security policy; --http is ignored\n");
            continue;
        }
        if(strncmp(a, "--http=", 7) == 0){
            fprintf(stderr, "Embedded HTTP interface is disabled by security policy; --http=* is ignored\n");
            continue;
        }
        pargv[parc++] = argv[i];
    }

    int argi = 1;
    if(parc > 1 && (pargv[1][0]<'0' || pargv[1][0]>'9')) argi = 2; /* backward compatible: ignore hosts.txt arg */

    g_default_interval_ms = (parc>argi) ? (u32)strtoul(pargv[argi],0,10) : 1000;
    int threads = (parc>argi+1)?atoi(pargv[argi+1]):64;
    g_default_timeout_ms = (parc>argi+2)?(u32)strtoul(pargv[argi+2],0,10):1000;
    g_default_down_threshold = (parc>argi+3)?(u32)strtoul(pargv[argi+3],0,10):3;
    g_history_len = (parc>argi+4)?(u32)strtoul(pargv[argi+4],0,10):512;
    (void)((parc>argi+5)?(u32)strtoul(pargv[argi+5],0,10):8080); /* reserved legacy arg slot: old http_port */
    u32 console_fps = (parc>argi+6)?(u32)strtoul(pargv[argi+6],0,10):1;
    g_db_path = (parc>argi+7)?pargv[argi+7]:"icmpmon.db";
    free(pargv);

    if(g_default_interval_ms < 50) g_default_interval_ms = 50;
    if(g_default_timeout_ms < 50) g_default_timeout_ms = 50;
    if(g_default_down_threshold < 1) g_default_down_threshold = 1;
    if(g_history_len < 16) g_history_len = 16;
    if(threads < 1) threads = 1;

    WSADATA w;
    if(WSAStartup(MAKEWORD(2,2), &w) != 0) return 1;
    QueryPerformanceFrequency(&g_qpf);

    fprintf(stderr, "Embedded HTTP: forcibly disabled (collector mode only)\n");

    InitializeSRWLock(&g_hosts_lock);
    InitializeSRWLock(&g_sched_lock);

    g_hosts = (Host*)calloc(g_hosts_cap, sizeof(Host));
    g_heap_cap = g_hosts_cap * 4;
    g_heap = (SchedNode*)calloc(g_heap_cap, sizeof(SchedNode));
    if(!g_hosts || !g_heap) return 1;
    for(int i=0;i<g_hosts_cap;i++) host_init_slot(&g_hosts[i]);

    int loaded = 0;

    g_icmp = IcmpCreateFile();
    if(g_icmp == INVALID_HANDLE_VALUE) return 1;

    InitializeSRWLock(&g_q_lock);
    g_q_cap = g_hosts_cap * 8;
    g_task_q = (Task*)calloc((size_t)g_q_cap, sizeof(Task));
    if(!g_task_q){ fprintf(stderr, "task queue alloc failed\n"); return 1; }
    g_sem = CreateSemaphoreW(NULL,0,0x7fffffff,NULL);
    InitializeSListHead(&g_dbq);
    g_dbsem = CreateSemaphoreW(NULL,0,0x7fffffff,NULL);

    db_init();
    loaded = db_load_hosts();
    fprintf(stderr,"loaded hosts from db: %d\n", loaded);
    db_sync_hosts();
    HANDLE hdb = CreateThread(NULL,0,db_thread,NULL,0,NULL);
    (void)hdb;

    int target_sweep_ms = 3000;
    LONG nh = g_n_hosts;
    int need_threads = (nh>0) ? (int)(((u64)nh * (u64)g_default_timeout_ms + target_sweep_ms - 1) / target_sweep_ms) : 1;
    if(need_threads < threads) need_threads = threads;
    if(need_threads > 1024) need_threads = 1024;
    threads = need_threads;
    fprintf(stderr, "workers: %d (auto-adjusted)\n", threads);
    for(int i=0;i<threads;i++) CreateThread(NULL,0,worker,NULL,0,NULL);
    /* Embedded HTTP server disabled by policy: ICMP collector stores data in DB only. */

    g_con = GetStdHandle(STD_OUTPUT_HANDLE);
    con_clear_all();

    u64 now = qpc_now();
    AcquireSRWLockExclusive(&g_sched_lock);
    for(int i=0;i<g_hosts_cap;i++) if(g_hosts[i].used){
        SchedNode n; n.host_id=i+1; n.gen=g_hosts[i].sched_gen; n.due_qpc=now;
        heap_push(n);
    }
    ReleaseSRWLockExclusive(&g_sched_lock);

    u64 render_step = ms_to_qpc(1000 / (console_fps?console_fps:1));
    if(render_step == 0) render_step = 1;
    u64 next_render = qpc_now() + render_step;

    for(;;){
        u64 wake = next_render;
        AcquireSRWLockShared(&g_sched_lock);
        if(g_heap_n > 0 && g_heap[0].due_qpc < wake) wake = g_heap[0].due_qpc;
        ReleaseSRWLockShared(&g_sched_lock);
        sleep_until_qpc(wake);

        now = qpc_now();
        if(now >= next_render){ do{ next_render += render_step; }while(next_render <= now); }

        for(;;){
            SchedNode sn;
            int have = 0;
            AcquireSRWLockExclusive(&g_sched_lock);
            if(g_heap_n > 0 && g_heap[0].due_qpc <= qpc_now()){ sn = heap_pop(); have = 1; }
            ReleaseSRWLockExclusive(&g_sched_lock);
            if(!have) break;
            if(sn.host_id < 1 || sn.host_id > g_hosts_cap) continue;

            Host* h = &g_hosts[sn.host_id-1];
            if(!h->used || sn.gen != h->sched_gen || !h->enabled) continue;

            if(InterlockedCompareExchange(&h->queued, 1, 0) == 0){
                if(!q_post(sn.host_id)) InterlockedExchange(&h->queued, 0);
            }

            u64 step = ms_to_qpc((u32)h->interval_ms);
            u64 next_due = sn.due_qpc + step;
            u64 tnow = qpc_now();
            while(next_due <= tnow) next_due += step;
            sn.due_qpc = next_due;
            AcquireSRWLockExclusive(&g_sched_lock);
            heap_push(sn);
            ReleaseSRWLockExclusive(&g_sched_lock);
        }
    }
    return 0;
}
