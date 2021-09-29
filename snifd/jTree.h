/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //            VES Utility:   A command line interface to libVES
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2018 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * jTree.h                    jTree: A binary tree
 *
 ***************************************************************************/

typedef struct jTree {
    void *data;
    void *extra;
    struct jTree *left;
    struct jTree *right;
    struct jTree *back;
    unsigned char ldepth;
    unsigned char rdepth;
} jTree;

#define jTree_new()	NULL
void **jTree_seek(struct jTree **ptree, void *term, void *arg, int (* cmpfn)(void *data, void *term, void *arg), unsigned char *depth);
void **jTree_first(struct jTree *jtree);
void **jTree_last(struct jTree *jtree);
void **jTree_next(void **pdata);
void **jTree_prev(void **pdata);
void jTree_delete(struct jTree **ptree, void **pdata);
unsigned char jTree_collapse(struct jTree **ptree);
