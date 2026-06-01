#include "fwknopd_common.h"

#ifdef FIREWALL_NFTABLES

#include "fw_util_nftables_json.h"
#include "string.h"

int json_string_field_get(json_t *j, const char *field, const char **s) {
    j = json_object_get(j, field);
    if (!json_is_string(j))
        return -1;
    *s = json_string_value(j);
    return 0;
}
int json_integer_field_get(json_t *j, const char *field, json_int_t *value) {
    j = json_object_get(j, field);
    if (!json_is_integer(j))
        return -1;
    *value = json_integer_value(j);
    return 0;
}

enum match_type {
    unknown,
    ip_saddr,
    ip_daddr,
    tcp_dport,
    udp_dport,
};
static enum match_type rule_match_type(json_t *left) {
    json_t *j = json_object_get(left, "payload");
    if (!j)
        return unknown;

    const char *proto;
    if (json_string_field_get(j, "protocol", &proto) != 0)
        return unknown;

    const char *field;
    if (json_string_field_get(j, "field", &field) != 0) 
        return unknown;
    
    if (strcmp(proto,"ip") == 0) {
        if (strcmp(field,"saddr") == 0)
            return ip_saddr;
        if (strcmp(field,"daddr") == 0)
            return ip_daddr;
    } else if (strcmp(proto,"tcp") == 0) {
        if (strcmp(field, "dport") == 0)
            return tcp_dport;
    } else if (strcmp(proto,"udp") == 0) {
        if (strcmp(field, "dport") == 0)
            return udp_dport;
    }
    return unknown;
}

static int rule_match_ipaddr_equals(json_t *right, const char *addr) {
    if (json_is_string(right))
        return strcmp(json_string_value(right), addr) == 0;

    if (json_is_object(right)) {
        json_t *prefix = json_object_get(right, "prefix");
        if (prefix && json_is_object(prefix)) {
            char buf[20]; // 111.111.111.111/11
            json_int_t j_len;
            const char *j_addr;
            if (json_integer_field_get(prefix, "len", &j_len) != 0)
                return 0;
            if (json_string_field_get(prefix, "addr", &j_addr) != 0)
                return 0;
            snprintf(buf, sizeof(buf), "%s/%u", j_addr, (unsigned)j_len);
            return strncmp(buf, addr, sizeof(buf)) == 0;
        }
    }

    return 0;
}
static int rule_match_port(json_t *right, unsigned int port) {
    return json_is_integer(right) && json_integer_value(right) == port;
}

int
rule_equals(json_t *rule,
            const char *saddr, const char *daddr,
            const char *proto, unsigned int dport,
            const char *target_chain)
{
    int found_saddr = !saddr;
    int found_daddr = !daddr;
    int found_proto_dport = (proto != NULL) && dport;
    int found_jump = 0;

    json_t *expr = json_object_get(rule, "expr");
    if (!json_is_array(expr))
        return 0;

    size_t expr_i;
    json_t *expr_v;
    json_array_foreach(expr, expr_i, expr_v) {
        json_t *match = json_object_get(expr_v, "match");
        if (json_is_object(match)) {
            json_t *left = json_object_get(match, "left");
            json_t *right = json_object_get(match, "right");

            enum match_type mtype = rule_match_type(left);
            if (mtype == ip_saddr) {
                if (rule_match_ipaddr_equals(right, saddr)) {
                    found_saddr = 1;
                    continue;
                } else {
                    return 0;
                }
            } else if (mtype == ip_daddr) {
                if (rule_match_ipaddr_equals(right, daddr)) {
                    found_daddr = 1;
                    continue;
                } else {
                    return 0;
                }
            } else if (mtype == tcp_dport) {
                if (!proto || strcmp(proto, "tcp") != 0 || dport == 0)
                    return 0;
                if (rule_match_port(right, dport)) {
                    found_proto_dport = 1;
                    continue;
                } else {
                    return 0;
                }
            } else if (mtype == udp_dport) {
                if (!proto || strcmp(proto, "udp") != 0 || dport == 0)
                    return 0;
                if (rule_match_port(right, dport)) {
                    found_proto_dport = 1;
                    continue;
                } else {
                    return 0;
                }
            } else { // a match that we didn't handle
                return 0;
            }

            continue;
        } else if (json_object_get(expr_v, "accept")) {
            if (target_chain && strcasecmp(target_chain, "accept") == 0) {
                found_jump = 1;
                continue;
            }
        } else if (json_object_get(expr_v, "drop")) {
            if (target_chain && strcasecmp(target_chain, "drop") == 0) {
                found_jump = 1;
                continue;
            }
        } else {
            json_t *jump_j = json_object_get(expr_v, "jump");
            if (json_is_object(jump_j)) {
                const char *jump_target;
                if (json_string_field_get(jump_j, "target", &jump_target) == 0) {
                    if (strcmp(jump_target, target_chain)) {
                        found_jump = 1;
                        continue;
                    }
                }
            }
        }
    }

    return found_saddr && found_daddr && found_proto_dport && found_jump;
}

#endif
