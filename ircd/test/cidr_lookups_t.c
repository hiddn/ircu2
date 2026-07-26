/* cidr_lookups_t.c - Test file for the CIDR lookup tree */

#include "ircd_log.h"
#include "ircd_string.h"
#include "res.h"
#include "cidr_lookups.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/** Parse \a text as an ipmask, aborting on failure.
 * @param[in] text CIDR mask to parse.
 * @param[out] addr Receives parsed address.
 * @param[out] bits Receives parsed prefix length.
 */
static void
parse_mask(const char *text, struct irc_in_addr *addr, unsigned char *bits)
{
    int res = ipmask_parse(text, addr, bits);
    assert(res != 0);
}

/** Add \a text to \a tree with associated \a data. */
static cidr_node *
add_mask(cidr_root_node *tree, const char *text, void *data)
{
    struct irc_in_addr addr;
    unsigned char bits;

    parse_mask(text, &addr, &bits);
    return cidr_add_node(tree, &addr, bits, data);
}

/** Find the best (most specific) match for \a text in \a tree.
 * @return The data pointer of the found node, or NULL if no match.
 */
static void *
search_best_data(cidr_root_node *tree, const char *text)
{
    struct irc_in_addr addr;
    unsigned char bits;
    cidr_node *node;

    parse_mask(text, &addr, &bits);
    node = cidr_search_best(tree, &addr, bits);
    return node ? node->data : 0;
}

/** Reference bit extractor: bit 0 is the most significant bit of
 * in6_16[0], matching the bit numbering used by _cidr_bit_diff().
 */
static unsigned int
ref_get_bit(const struct irc_in_addr *ip, unsigned int bit_index)
{
    unsigned short word = ntohs(ip->in6_16[bit_index / 16]);
    return (word >> (15 - (bit_index % 16))) & 1;
}

/** Check _cidr_get_bit() against the reference for every bit index. */
static void
test_get_bit(void)
{
    static const char *test_addrs[] = {
        "8000::",
        "1:2:3:4:5:6:7:8",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::1",
        "::1",
        0
    };
    struct irc_in_addr addr;
    unsigned char bits;
    unsigned int ii, bit;

    for (ii = 0; test_addrs[ii]; ++ii) {
        parse_mask(test_addrs[ii], &addr, &bits);
        for (bit = 0; bit < 128; ++bit) {
            unsigned int got = _cidr_get_bit(&addr, bit) ? 1 : 0;
            unsigned int want = ref_get_bit(&addr, bit);
            if (got != want) {
                printf("Failed: _cidr_get_bit(%s, %u) = %u, expected %u\n",
                       test_addrs[ii], bit, got, want);
                assert(got == want);
            }
        }
    }
    printf("Passed: _cidr_get_bit\n");
}

/** Prefixes that diverge at bit 0 must both stay reachable. */
static void
test_bit0_divergence(void)
{
    cidr_root_node *tree = cidr_new_tree();
    static int data_low, data_high;

    assert(tree != 0);
    assert(add_mask(tree, "2001:db8::/32", &data_low) != 0);
    assert(add_mask(tree, "8000::/16", &data_high) != 0);

    assert(search_best_data(tree, "2001:db8::1") == &data_low);
    assert(search_best_data(tree, "8000::1") == &data_high);
    assert(search_best_data(tree, "4000::1") == 0);
    printf("Passed: bit 0 divergence\n");
}

/** Basic add/find/most-specific-match behavior for both families. */
static void
test_add_find(void)
{
    cidr_root_node *tree = cidr_new_tree();
    static int data_v4_wide, data_v4_narrow, data_v4_host;
    static int data_v6_wide, data_v6_narrow;
    struct irc_in_addr addr;
    unsigned char bits;

    assert(tree != 0);
    assert(add_mask(tree, "10.0.0.0/8", &data_v4_wide) != 0);
    assert(add_mask(tree, "10.20.0.0/16", &data_v4_narrow) != 0);
    assert(add_mask(tree, "10.20.30.40", &data_v4_host) != 0);
    assert(add_mask(tree, "2001:db8::/32", &data_v6_wide) != 0);
    assert(add_mask(tree, "2001:db8:1::/48", &data_v6_narrow) != 0);

    /* Most specific match wins. */
    assert(search_best_data(tree, "10.20.30.40") == &data_v4_host);
    assert(search_best_data(tree, "10.20.30.41") == &data_v4_narrow);
    assert(search_best_data(tree, "10.30.0.1") == &data_v4_wide);
    assert(search_best_data(tree, "11.0.0.1") == 0);
    assert(search_best_data(tree, "2001:db8:1::5") == &data_v6_narrow);
    assert(search_best_data(tree, "2001:db8:2::5") == &data_v6_wide);
    assert(search_best_data(tree, "2001:db9::5") == 0);

    /* IPv4 lookups must not match IPv6 entries and vice versa. */
    assert(search_best_data(tree, "1.2.3.4") == 0);

    /* Walking up from a covered address visits broader entries. */
    parse_mask("10.20.30.40", &addr, &bits);
    {
        cidr_node *node = cidr_search_best(tree, &addr, bits);
        assert(node != 0 && node->data == &data_v4_host);
        node = node->parent;
        while (node && !node->data)
            node = node->parent;
        assert(node != 0 && node->data == &data_v4_narrow);
    }

    /* Exact lookups. */
    parse_mask("10.20.0.0/16", &addr, &bits);
    assert(cidr_get_data(tree, &addr, bits) == &data_v4_narrow);
    parse_mask("10.21.0.0/16", &addr, &bits);
    assert(cidr_get_data(tree, &addr, bits) == 0);

    /* Removal by mask. */
    parse_mask("10.20.0.0/16", &addr, &bits);
    assert(cidr_rem_node_by_cidr(tree, &addr, bits) == 1);
    assert(search_best_data(tree, "10.20.30.41") == &data_v4_wide);
    assert(search_best_data(tree, "10.20.30.40") == &data_v4_host);
    printf("Passed: add/find/remove\n");
}

int
main(int argc, char *argv[])
{
    test_get_bit();
    test_bit0_divergence();
    test_add_find();
    printf("Done.\n");
    return 0;
}
