#ifndef FW_UTIL_NFTABLES_JSON_H
#define FW_UTIL_NFTABLES_JSON_H

#include <jansson.h>

int json_string_field_get(json_t *j, const char *field, const char **s);
int json_integer_field_get(json_t *j, const char *field, json_int_t *value);
int rule_equals(json_t *rule,
                const char *saddr, const char *daddr,
                const char *proto, unsigned int dport,
                const char *target_chain);

#endif