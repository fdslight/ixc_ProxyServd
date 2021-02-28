#ifndef __MAP_H
#define __MAP_H

typedef unsigned char map_ksize_t;
typedef void (*map_del_func_t)(void *);
typedef void (*map_each_func_t)(void *);

struct __map_list;

struct map_node{
    struct map_node *previous;
    struct map_node *next[256];
    struct __map_list *list;
    void *data;
    // reference count
    unsigned long long refcnt[256];
    unsigned short slot_flags;
    //
    unsigned char key_v;
};

struct map{
    void *priv_data;
    struct map_node *root;
    struct __map_list *list_header;
    struct __map_list *list_end;
    unsigned long long __dbg_malloc_cnt;
    unsigned long long __dbg_free_cnt;
    map_ksize_t length;
};

struct __map_list{
    struct map_node *node;
    struct __map_list *next;
    struct __map_list *previous;
};

int map_new(struct map **map,map_ksize_t length);
void map_release(struct map *map,map_del_func_t func);

int map_add(struct map *map,const char *key,void *data);
void map_del(struct map *map,const char *key,map_del_func_t func);
void *map_find(struct map *map,const char *key,char *is_find);
void map_each(struct map *map,map_each_func_t func);

#endif